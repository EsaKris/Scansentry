from datetime import datetime, timedelta, timezone

import pytest
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction

from apps.credits import service
from apps.credits.models import CreditLot, UsageCreditLedger, UsageCreditWallet

pytestmark = pytest.mark.django_db
T = UsageCreditLedger.Type
NOW = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)


def grant(user, amount=10, key="k1", expires=None, tx=T.ADMIN_GRANT, now=NOW):
    return service.grant(user, amount, tx, idempotency_key=key, reason="test", expires_at=expires, now=now)


def test_a_new_wallet_starts_at_zero(user):
    assert service.balance_of(user, NOW) == 0


def test_grant_adds_credits_and_writes_a_ledger_entry(user):
    entry, created = grant(user, 10)
    assert created and entry.amount == 10 and entry.balance_after == 10
    assert service.balance_of(user, NOW) == 10
    assert UsageCreditLedger.objects.filter(user=user).count() == 1


def test_the_same_idempotency_key_never_credits_twice(user):
    a, c1 = grant(user, 10, key="same")
    b, c2 = grant(user, 10, key="same")
    assert (c1, c2) == (True, False) and a.pk == b.pk
    assert service.balance_of(user, NOW) == 10
    assert UsageCreditLedger.objects.count() == 1 and CreditLot.objects.count() == 1


def test_reusing_a_key_for_something_different_is_refused(user, other_user):
    grant(user, 10, key="same")
    with pytest.raises(service.IdempotencyConflict):
        grant(user, 99, key="same")
    with pytest.raises(service.IdempotencyConflict):
        grant(other_user, 10, key="same")
    assert service.balance_of(user, NOW) == 10 and service.balance_of(other_user, NOW) == 0


def test_spend_reduces_balance_and_records_the_feature(user):
    grant(user, 10)
    e = service.spend(user, 3, feature_key="domain.lookups", idempotency_key="s1", now=NOW)
    assert e.amount == -3 and e.balance_after == 7 and e.feature_key == "domain.lookups"
    assert service.balance_of(user, NOW) == 7


def test_spending_more_than_the_balance_is_refused_and_changes_nothing(user):
    grant(user, 5)
    with pytest.raises(service.InsufficientCredits):
        service.spend(user, 6, feature_key="x", idempotency_key="s1", now=NOW)
    assert service.balance_of(user, NOW) == 5
    assert UsageCreditLedger.objects.filter(user=user).count() == 1
    assert service.reconcile()["consistent"]


def test_the_same_credits_cannot_be_spent_twice(user):
    grant(user, 5)
    service.spend(user, 5, feature_key="x", idempotency_key="a", now=NOW)
    with pytest.raises(service.InsufficientCredits):
        service.spend(user, 5, feature_key="x", idempotency_key="b", now=NOW)
    assert service.balance_of(user, NOW) == 0


def test_a_retried_spend_with_the_same_key_is_applied_once(user):
    grant(user, 10)
    a = service.spend(user, 4, feature_key="x", idempotency_key="retry", now=NOW)
    b = service.spend(user, 4, feature_key="x", idempotency_key="retry", now=NOW)
    assert a.pk == b.pk and service.balance_of(user, NOW) == 6


def test_the_conditional_update_is_what_stops_an_overdraw(user):
    """Even if the lock is bypassed (SQLite has none), the balance guard refuses a debit that would go below zero."""
    grant(user, 5)
    w = UsageCreditWallet.objects.get(user=user)
    assert UsageCreditWallet.objects.filter(pk=w.pk, available_balance__gte=6).update(available_balance=w.available_balance - 6) == 0
    with pytest.raises(IntegrityError), transaction.atomic():           # and the database itself refuses a negative balance
        UsageCreditWallet.objects.filter(pk=w.pk).update(available_balance=-1)


def test_amounts_must_be_positive_whole_numbers(user):
    for bad in (0, -5, 1.5, True):
        with pytest.raises(ValueError):
            service.grant(user, bad, T.ADMIN_GRANT, idempotency_key=f"bad{bad}")
        with pytest.raises(ValueError):
            service.debit(user, bad, T.ADMIN_REVERSAL, idempotency_key=f"bad{bad}")
    with pytest.raises(ValueError):
        service.grant(user, 5, T.FEATURE_USAGE, idempotency_key="wrong-type")       # a debit type cannot be used to add credits
    with pytest.raises(ValueError):
        service.debit(user, 5, T.ADMIN_GRANT, idempotency_key="wrong-type2")


def test_the_database_enforces_the_sign_of_each_entry_type(user):
    w = service.wallet_for(user)
    with pytest.raises(IntegrityError), transaction.atomic():
        UsageCreditLedger.objects.create(wallet=w, user=user, transaction_type=T.ADMIN_GRANT, amount=-5, balance_after=0, idempotency_key="neg")
    with pytest.raises(IntegrityError), transaction.atomic():
        UsageCreditLedger.objects.create(wallet=w, user=user, transaction_type=T.FEATURE_USAGE, amount=5, balance_after=0, idempotency_key="pos")


def test_ledger_entries_are_append_only(user):
    entry, _ = grant(user, 10)
    entry.reason = "changed"
    with pytest.raises(ValidationError):
        entry.save()
    with pytest.raises(ValidationError):
        entry.delete()
    entry.refresh_from_db()
    assert entry.reason == "test"


def test_credits_are_per_user(user, other_user):
    grant(user, 10)
    assert service.balance_of(other_user, NOW) == 0
    with pytest.raises(service.InsufficientCredits):
        service.spend(other_user, 1, feature_key="x", idempotency_key="o", now=NOW)


# ---- expiry ------------------------------------------------------------------------------------------------------------------
def test_expired_credits_cannot_be_spent_and_are_removed_with_a_ledger_entry(user):
    grant(user, 10, expires=NOW + timedelta(days=1))
    later = NOW + timedelta(days=2)
    with pytest.raises(service.InsufficientCredits):
        service.spend(user, 1, feature_key="x", idempotency_key="s", now=later)
    assert service.balance_of(user, later) == 0
    expiry = UsageCreditLedger.objects.get(transaction_type=T.CREDIT_EXPIRY)
    assert expiry.amount == -10 and expiry.balance_after == 0
    assert service.reconcile()["consistent"]


def test_expiry_is_recorded_once_however_often_it_runs(user):
    grant(user, 10, expires=NOW + timedelta(days=1))
    later = NOW + timedelta(days=2)
    for _ in range(3):
        service.expire_due(user, later)
    assert UsageCreditLedger.objects.filter(transaction_type=T.CREDIT_EXPIRY).count() == 1


def test_credits_without_an_expiry_never_expire(user):
    grant(user, 10, expires=None)
    assert service.balance_of(user, NOW + timedelta(days=3650)) == 10


def test_soonest_expiring_credits_are_spent_first(user):
    grant(user, 5, key="late", expires=NOW + timedelta(days=30))
    grant(user, 5, key="soon", expires=NOW + timedelta(days=2))
    grant(user, 5, key="never", expires=None)
    service.spend(user, 5, feature_key="x", idempotency_key="s1", now=NOW)
    lots = {l.entry.idempotency_key: l.remaining for l in CreditLot.objects.select_related("entry")}
    assert lots == {"soon": 0, "late": 5, "never": 5}
    # the credits that were NOT spent keep their own expiry, so only they can expire later
    after = NOW + timedelta(days=40)
    assert service.balance_of(user, after) == 5


def test_a_spend_spanning_several_lots_is_consistent(user):
    grant(user, 3, key="a", expires=NOW + timedelta(days=1))
    grant(user, 3, key="b", expires=NOW + timedelta(days=2))
    service.spend(user, 5, feature_key="x", idempotency_key="s", now=NOW)
    assert sorted(l.remaining for l in CreditLot.objects.all()) == [0, 1]
    assert service.balance_of(user, NOW) == 1 and service.reconcile()["consistent"]


# ---- refund / reversal / consistency -----------------------------------------------------------------------------------------
def test_refund_gives_back_a_failed_use_once(user):
    grant(user, 10)
    spent = service.spend(user, 4, feature_key="domain.lookups", idempotency_key="s", now=NOW)
    service.refund_usage(spent)
    service.refund_usage(spent)                                      # a retry must not double-refund
    assert service.balance_of(user, NOW) == 10
    assert UsageCreditLedger.objects.filter(transaction_type=T.USAGE_REFUND).count() == 1


def test_only_feature_spending_can_be_refunded(user):
    entry, _ = grant(user, 10)
    with pytest.raises(ValueError):
        service.refund_usage(entry)


def test_admin_reversal_removes_credits_but_never_below_zero(user):
    grant(user, 10)
    service.debit(user, 4, T.ADMIN_REVERSAL, idempotency_key="r1", reason="mistake", now=NOW)
    assert service.balance_of(user, NOW) == 6
    with pytest.raises(service.InsufficientCredits):
        service.debit(user, 7, T.ADMIN_REVERSAL, idempotency_key="r2", reason="too much", now=NOW)
    assert service.balance_of(user, NOW) == 6


def test_wallet_ledger_and_lots_always_agree(user, other_user):
    grant(user, 10, key="a", expires=NOW + timedelta(days=1))
    grant(user, 7, key="b")
    grant(other_user, 4, key="c")
    service.spend(user, 6, feature_key="x", idempotency_key="s1", now=NOW)
    service.debit(user, 2, T.ADMIN_REVERSAL, idempotency_key="r", now=NOW)
    service.expire_due(user, NOW + timedelta(days=5))
    r = service.reconcile()
    assert r["consistent"], r
    assert r["wallet_total"] == r["ledger_total"] == r["lot_total"]


def test_summary_reports_lifetime_totals_and_expiring_credits(user):
    grant(user, 10, key="a", tx=T.REWARDED_AD_EARNED, expires=NOW + timedelta(days=5))
    service.spend(user, 3, feature_key="x", idempotency_key="s", now=NOW)
    s = service.summary(user, NOW)
    assert s["available_balance"] == 7 and s["lifetime"]["earned_from_rewarded_ads"] == 10 and s["lifetime"]["spent"] == 3
    assert s["expiring"] == [{"amount": 7, "expires_at": NOW + timedelta(days=5)}]
