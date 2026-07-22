"""TLDs with disproportionate abuse rates.

Sources: Spamhaus "most abused TLDs" reporting and the free/near-free
registrars' zones historically favored by phishing kits. Presence here is a
weak signal on its own (plenty of legitimate .xyz sites exist) — hence the
modest weight in scoring.
"""

SUSPICIOUS_TLDS: frozenset[str] = frozenset(
    {
        # free Freenom zones — historically phishing-dense
        "tk", "ml", "gq", "cf", "ga",
        # cheap bulk-registration favorites
        "top", "xyz", "icu", "club", "work", "rest", "fit", "loan",
        "download", "racing", "review", "stream", "gdn", "mom", "lol",
        "pw", "bid", "win", "vip", "monster", "quest", "cam", "sbs",
        "cfd", "cyou", "buzz", "boats", "hair", "beauty", "skin", "makeup",
        # file-extension collision TLDs (deception via 'attachment.zip')
        "zip", "mov",
    }
)
