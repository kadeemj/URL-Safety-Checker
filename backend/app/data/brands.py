"""Frequently-impersonated brands, as registrable domains.

Phishing overwhelmingly targets a small set of high-value brands (payment,
cloud, shipping, banking). This list powers the typosquatting, homoglyph,
and keyword-bait checks. Kept deliberately small and high-signal: every
entry here is a brand with well-documented phishing campaigns.
"""

BRAND_DOMAINS: frozenset[str] = frozenset(
    {
        # payments / fintech
        "paypal.com",
        "venmo.com",
        "cash.app",
        "zellepay.com",
        "wise.com",
        "stripe.com",
        # crypto
        "coinbase.com",
        "binance.com",
        "kraken.com",
        "blockchain.com",
        "metamask.io",
        # big tech
        "google.com",
        "gmail.com",
        "youtube.com",
        "apple.com",
        "icloud.com",
        "microsoft.com",
        "outlook.com",
        "office.com",
        "live.com",
        "amazon.com",
        "facebook.com",
        "instagram.com",
        "whatsapp.com",
        "telegram.org",
        "twitter.com",
        "linkedin.com",
        "netflix.com",
        "spotify.com",
        "adobe.com",
        "dropbox.com",
        "github.com",
        "zoom.us",
        "slack.com",
        "docusign.com",
        # banks / cards
        "chase.com",
        "wellsfargo.com",
        "bankofamerica.com",
        "citibank.com",
        "capitalone.com",
        "americanexpress.com",
        "discover.com",
        "usbank.com",
        "hsbc.com",
        "barclays.com",
        # retail / shipping / gov
        "walmart.com",
        "target.com",
        "costco.com",
        "ebay.com",
        "shopify.com",
        "usps.com",
        "ups.com",
        "fedex.com",
        "dhl.com",
        "irs.gov",
        # gaming
        "steampowered.com",
        "steamcommunity.com",
        "roblox.com",
        "epicgames.com",
    }
)

# The distinctive left-most label of each brand domain ("paypal", "chase", ...)
BRAND_LABELS: frozenset[str] = frozenset(d.split(".")[0] for d in BRAND_DOMAINS)
