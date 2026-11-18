"""Real parallel-load tests for credit spending and reward settlement.

These need a database with true row locking, so they run only against PostgreSQL:
    TEST_DATABASE_URL=postgresql://user:pass@host:5432/db pytest tests/test_concurrency.py
On SQLite (the default) they are skipped: its single writer lock makes them meaningless.
"""
import threading
import time

import pytest
from django.db import connection, connections

from apps.credits import service
from apps.credits.models import RewardedAdSession, UsageCreditLedger, UsageCreditWallet
from tests.conftest import set_config, start_session

T = UsageCreditLedger.Type
pytestmark = [pytest.mark.django_db(transaction=True),
              pytest.mark.skipif(connection.vendor != "postgresql", reason="needs PostgreSQL row locking")]


def run_parallel(n, fn):
    """Run fn(i) in n threads released at the same instant. Returns (results, errors)."""
    barrier, results, errors = threading.Barrier(n), [None] * n, []

    def worker(i):
        try:
            barrier.wait(timeout=10)
            results[i] = fn(i)
        except Exception as e:                       # noqa: BLE001 - collected and asserted on
            errors.append(e)
        finally:
            connections.close_all()

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    [t.start() for t in threads]
    [t.join(timeout=60) for t in threads]
    return results, errors


def test_parallel_spends_can_never_overdraw(user):
    service.grant(user, 10, T.ADMIN_GRANT, idempotency_key="seed")

    def spend(i):
        try:
            service.spend(user, 1, feature_key="domain.lookups", idempotency_key=f"s{i}")
            return "ok"
        except service.InsufficientCredits:
            return "refused"

    results, errors = run_parallel(30, spend)
    assert not errors, errors
    assert results.count("ok") == 10 and results.count("refused") == 20          # exactly the balance, never more
    assert service.balance_of(user) == 0
    assert service.reconcile()["consistent"]
    assert UsageCreditLedger.objects.filter(transaction_type=T.FEATURE_USAGE).count() == 10


def test_parallel_spends_of_the_same_request_apply_once(user):
    service.grant(user, 10, T.ADMIN_GRANT, idempotency_key="seed")
    results, errors = run_parallel(20, lambda i: service.spend(user, 3, feature_key="x", idempotency_key="same-request").pk)
    assert not errors, errors
    assert len(set(results)) == 1 and service.balance_of(user) == 7
    assert UsageCreditLedger.objects.filter(transaction_type=T.FEATURE_USAGE).count() == 1


def test_parallel_grants_with_one_key_credit_once(user):
    results, errors = run_parallel(20, lambda i: service.grant(user, 5, T.ADMIN_GRANT, idempotency_key="one-key")[1])
    assert not errors, errors
    assert results.count(True) == 1 and service.balance_of(user) == 5
    assert UsageCreditLedger.objects.filter(idempotency_key="one-key").count() == 1


def test_parallel_mixed_grants_and_spends_stay_consistent(user):
    service.grant(user, 50, T.ADMIN_GRANT, idempotency_key="seed")

    def act(i):
        if i % 2:
            service.grant(user, 2, T.PROMOTIONAL_CREDIT, idempotency_key=f"g{i}")
        else:
            try:
                service.spend(user, 3, feature_key="x", idempotency_key=f"s{i}")
            except service.InsufficientCredits:
                pass

    _, errors = run_parallel(40, act)
    assert not errors, errors
    r = service.reconcile()
    assert r["consistent"], r
    assert UsageCreditWallet.objects.get(user=user).available_balance >= 0


def test_parallel_duplicate_callbacks_reward_exactly_once(admob, auth_client, rewards_on, user):
    from rest_framework.test import APIClient
    _d, sess = start_session(auth_client, rewards_on.offer)
    url = "/api/v1/advertising/reward-callbacks/admob/?" + admob.query(sess)
    results, errors = run_parallel(15, lambda i: APIClient().get(url).data["code"])
    assert not errors, errors
    assert results.count("accepted") == 1 and results.count("duplicate") == 14
    assert service.balance_of(user) == 5 and UsageCreditLedger.objects.filter(transaction_type=T.REWARDED_AD_EARNED).count() == 1
    assert RewardedAdSession.objects.get(pk=sess.pk).status == "rewarded"


def test_parallel_callbacks_for_different_sessions_of_one_user_respect_the_claim_cap(admob, auth_client, rewards_on, user):
    from apps.credits.models import RewardedAdOffer
    from rest_framework.test import APIClient
    RewardedAdOffer.objects.filter(pk=rewards_on.offer.pk).update(maximum_claims_per_day=2)
    sessions = []
    for _ in range(12):                              # twelve opened-and-abandoned sessions that each later get a genuine completion
        _d, s = start_session(auth_client, rewards_on.offer)
        RewardedAdSession.objects.filter(pk=s.pk).update(status="closed_without_reward")
        sessions.append(s)
    urls = ["/api/v1/advertising/reward-callbacks/admob/?" + admob.query(s, tx=f"tx-{i}") for i, s in enumerate(sessions)]
    results, errors = run_parallel(12, lambda i: APIClient().get(urls[i]).data["code"])
    assert not errors, errors
    granted = results.count("accepted")
    assert granted <= 2, results                      # the cap holds under a simultaneous burst
    assert service.balance_of(user) == 5 * granted and service.reconcile()["consistent"]
