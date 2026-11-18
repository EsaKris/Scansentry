from .base import PaymentProvider, ProviderError
from .flutterwave import FlutterwaveProvider
from .paystack import PaystackProvider

PROVIDERS: dict[str, type[PaymentProvider]] = {
    PaystackProvider.key: PaystackProvider,
    FlutterwaveProvider.key: FlutterwaveProvider,
}

# Not implemented yet (listed so administrators see the roadmap honestly).
PLANNED = {
    "stripe": "Not implemented. Add an adapter (checkout session + signed webhooks) before enabling.",
    "google_play": ("Not implemented. Google Play policy requires Google Play Billing for digital subscriptions sold inside "
                    "the Android app; purchase-token verification needs the Google Play Developer API."),
}


def get_provider(key: str, guard=None) -> PaymentProvider | None:
    cls = PROVIDERS.get(key)
    return cls(guard) if cls else None
