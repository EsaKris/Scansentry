"""Wallet and ledger operations. Every function is atomic and idempotent by key.

Guarantees (each covered by tests):
  * the ledger is the record of truth; wallet balance == sum(ledger) == sum(unspent lots)
  * a debit is a conditional UPDATE (`balance >= amount`), so two concurrent spends can never overdraw, even without row locks
  * the same idempotency key never creates a second entry; reusing it for something different is refused
  * expired credits are never spendable, and soonest-expiring credits are spent first
"""
from datetime import datetime, timedelta, timezone

from django.db import IntegrityError, transaction
from django.db.models import F, Q, Sum

from .models import CreditLot, UsageCreditLedger, UsageCreditWallet

T = UsageCreditLedger.Type


class CreditError(Exception):
    code = "credit_error"


class InsufficientCredits(CreditError):
    code = "insufficient_credits"


class IdempotencyConflict(CreditError):
    code = "idempotency_conflict"


class InvariantViolation(CreditError):
    code = "credit_invariant_violation"


def _now(now=None) -> datetime:
    return now or datetime.now(timezone.utc)


def wallet_for(user, *, lock: bool = False) -> UsageCreditWallet:
    wallet, _ = UsageCreditWallet.objects.get_or_create(user=user)
    if lock:
        wallet = UsageCreditWallet.objects.select_for_update().get(pk=wallet.pk)
    return wallet


def _existing(key: str, *, user, amount: int, tx_type: str):
    entry = UsageCreditLedger.objects.filter(idempotency_key=key).first()
    if entry is None:
        return None
    if entry.user_id != user.pk or entry.amount != amount or entry.transaction_type != tx_type:
        raise IdempotencyConflict("This idempotency key was already used for a different credit movement.")
    return entry


def _expire_due(wallet: UsageCreditWallet, now: datetime) -> int:
    """Turn expired, unspent credits into CREDIT_EXPIRY ledger entries. Must run inside a transaction holding the wallet lock."""
    expired = 0
    lots = (CreditLot.objects.select_for_update().filter(wallet=wallet, remaining__gt=0, expires_at__lte=now)
            .select_related("entry").order_by("expires_at", "pk"))
    for lot in lots:
        gone = lot.remaining
        UsageCreditWallet.objects.filter(pk=wallet.pk).update(available_balance=F("available_balance") - gone)
        balance = UsageCreditWallet.objects.values_list("available_balance", flat=True).get(pk=wallet.pk)
        UsageCreditLedger.objects.create(
            wallet=wallet, user=wallet.user, transaction_type=T.CREDIT_EXPIRY, amount=-gone, balance_after=balance,
            feature_key=lot.entry.feature_key, idempotency_key=f"expire:{lot.pk}",
            reason=f"Credits earned on {lot.created_at:%Y-%m-%d} expired.")
        CreditLot.objects.filter(pk=lot.pk).update(remaining=0)
        expired += gone
    return expired


def expire_due(user, now=None) -> int:
    with transaction.atomic():
        wallet = wallet_for(user, lock=True)
        return _expire_due(wallet, _now(now))


def grant(user, amount: int, tx_type: str, *, idempotency_key: str, reason: str = "", feature_key: str = "", session=None,
          provider_transaction_id: str = "", expires_at: datetime | None = None, now=None):
    """Add credits. Returns (entry, created). Repeating the same key returns the original entry and changes nothing."""
    if tx_type not in [t.value for t in UsageCreditLedger.CREDIT_TYPES]:
        raise ValueError("grant() only creates credit entries")
    if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
        raise ValueError("A credit amount must be a positive whole number.")
    with transaction.atomic():
        wallet = wallet_for(user, lock=True)
        found = _existing(idempotency_key, user=user, amount=amount, tx_type=tx_type)
        if found is not None:
            return found, False
        try:
            with transaction.atomic():          # savepoint: a racing duplicate key must not poison the outer transaction
                UsageCreditWallet.objects.filter(pk=wallet.pk).update(available_balance=F("available_balance") + amount)
                balance = UsageCreditWallet.objects.values_list("available_balance", flat=True).get(pk=wallet.pk)
                entry = UsageCreditLedger.objects.create(
                    wallet=wallet, user=user, transaction_type=tx_type, amount=amount, balance_after=balance,
                    feature_key=feature_key, rewarded_ad_session=session, provider_transaction_id=provider_transaction_id,
                    idempotency_key=idempotency_key, reason=reason[:300])
                CreditLot.objects.create(entry=entry, wallet=wallet, amount=amount, remaining=amount, expires_at=expires_at)
        except IntegrityError:
            found = _existing(idempotency_key, user=user, amount=amount, tx_type=tx_type)
            if found is None:
                raise
            return found, False
        return entry, True


def _take(wallet: UsageCreditWallet, amount: int, now: datetime) -> None:
    """Consume `amount` from the spendable lots, soonest-expiring first. Raises if the lots cannot cover it."""
    lots = (CreditLot.objects.select_for_update().filter(wallet=wallet, remaining__gt=0)
            .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
            .order_by(F("expires_at").asc(nulls_last=True), "created_at", "pk"))
    left = amount
    for lot in lots:
        use = min(lot.remaining, left)
        CreditLot.objects.filter(pk=lot.pk).update(remaining=F("remaining") - use)
        left -= use
        if left == 0:
            return
    raise InvariantViolation("The wallet balance and its credit lots disagree.")        # rolls the whole transaction back


def debit(user, amount: int, tx_type: str, *, idempotency_key: str, reason: str = "", feature_key: str = "", now=None):
    """Remove credits atomically. Raises InsufficientCredits (and changes nothing) when the spendable balance is too small."""
    if tx_type not in [t.value for t in UsageCreditLedger.DEBIT_TYPES] or tx_type == T.CREDIT_EXPIRY:
        raise ValueError("debit() creates spend/reversal entries only")
    if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
        raise ValueError("A debit amount must be a positive whole number.")
    now = _now(now)
    with transaction.atomic():
        wallet = wallet_for(user, lock=True)
        found = _existing(idempotency_key, user=user, amount=-amount, tx_type=tx_type)
        if found is not None:
            return found
        _expire_due(wallet, now)
        # The conditional UPDATE is the double-spend guard: it succeeds only while enough credits remain.
        if not UsageCreditWallet.objects.filter(pk=wallet.pk, available_balance__gte=amount).update(
                available_balance=F("available_balance") - amount):
            raise InsufficientCredits("There are not enough ScanSentry Credits.")
        _take(wallet, amount, now)
        balance = UsageCreditWallet.objects.values_list("available_balance", flat=True).get(pk=wallet.pk)
        return UsageCreditLedger.objects.create(
            wallet=wallet, user=user, transaction_type=tx_type, amount=-amount, balance_after=balance,
            feature_key=feature_key, idempotency_key=idempotency_key, reason=reason[:300])


def spend(user, amount: int, *, feature_key: str, idempotency_key: str, reason: str = "", now=None):
    return debit(user, amount, T.FEATURE_USAGE, idempotency_key=idempotency_key, feature_key=feature_key,
                 reason=reason or f"Used on {feature_key}", now=now)


def refund_usage(entry: UsageCreditLedger):
    """Give back credits spent on a use that then failed. Once per spend; the refund never expires."""
    if entry.transaction_type != T.FEATURE_USAGE:
        raise ValueError("Only feature spending can be refunded.")
    refunded, _ = grant(entry.user, -entry.amount, T.USAGE_REFUND, idempotency_key=f"refund:{entry.pk}",
                        feature_key=entry.feature_key, reason=f"Refund: the {entry.feature_key} request failed.")
    return refunded


def balance_of(user, now=None) -> int:
    """Spendable balance (expired credits are removed first)."""
    with transaction.atomic():
        wallet = wallet_for(user, lock=True)
        _expire_due(wallet, _now(now))
        return UsageCreditWallet.objects.values_list("available_balance", flat=True).get(pk=wallet.pk)


def summary(user, now=None) -> dict:
    now = _now(now)
    balance = balance_of(user, now)
    wallet = wallet_for(user)
    sums = dict(UsageCreditLedger.objects.filter(user=user).values_list("transaction_type").annotate(s=Sum("amount")))
    soon = (CreditLot.objects.filter(wallet=wallet, remaining__gt=0, expires_at__isnull=False, expires_at__gt=now)
            .order_by("expires_at").values("remaining", "expires_at"))
    return {
        "available_balance": balance,
        "lifetime": {
            "earned_from_rewarded_ads": sums.get(T.REWARDED_AD_EARNED, 0),
            "other_credits": sums.get(T.PROMOTIONAL_CREDIT, 0) + sums.get(T.ADMIN_GRANT, 0) + sums.get(T.USAGE_REFUND, 0),
            "spent": -sums.get(T.FEATURE_USAGE, 0),
            "expired": -sums.get(T.CREDIT_EXPIRY, 0),
            "removed_by_administrator": -sums.get(T.ADMIN_REVERSAL, 0),
        },
        "expiring": [{"amount": r["remaining"], "expires_at": r["expires_at"]} for r in soon[:5]],
        "earning_suspended": wallet.earning_suspended,
    }


def reconcile() -> dict:
    """Are the three records of credit in agreement? Used by the admin overview and tests."""
    ledger = UsageCreditLedger.objects.aggregate(s=Sum("amount"))["s"] or 0
    wallets = UsageCreditWallet.objects.aggregate(s=Sum("available_balance"))["s"] or 0
    lots = CreditLot.objects.aggregate(s=Sum("remaining"))["s"] or 0
    per_wallet_bad = 0
    for w in UsageCreditWallet.objects.all():
        total = UsageCreditLedger.objects.filter(wallet=w).aggregate(s=Sum("amount"))["s"] or 0
        if total != w.available_balance:
            per_wallet_bad += 1
    return {"ledger_total": ledger, "wallet_total": wallets, "lot_total": lots, "mismatched_wallets": per_wallet_bad,
            "consistent": ledger == wallets == lots and per_wallet_bad == 0}


def expiry_for(days: int | None, now: datetime) -> datetime | None:
    return None if not days else now + timedelta(days=days)
