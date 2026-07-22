"""URL shortening services, as registrable domains.

A shortener is not malicious — but it hides the true destination, which
defeats every other check a user (or this tool) could run on the visible
URL. Scored as an opacity penalty, not an accusation.
"""

SHORTENER_DOMAINS: frozenset[str] = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "v.gd",
        "buff.ly",
        "ow.ly",
        "rebrand.ly",
        "cutt.ly",
        "rb.gy",
        "shorturl.at",
        "tiny.cc",
        "lnkd.in",
        "s.id",
        "t.ly",
        "adf.ly",
        "bl.ink",
        "snip.ly",
        "qr.ae",
    }
)
