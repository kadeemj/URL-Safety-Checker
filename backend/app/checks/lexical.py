"""Lexical checks: does the URL's *text* try to impersonate something?"""

import re
import unicodedata

from app.checks.base import CheckCategory, CheckResult, CheckStatus
from app.data.brands import BRAND_DOMAINS, BRAND_LABELS
from app.data.homoglyphs import CONFUSABLES
from app.data.shorteners import SHORTENER_DOMAINS
from app.data.suspicious_tlds import SUSPICIOUS_TLDS
from app.domains import extract, registrable_domain
from app.validation import ValidatedURL

BAIT_TOKENS = frozenset(
    {
        "login", "signin", "logon", "verify", "verification", "secure",
        "security", "account", "update", "confirm", "password", "banking",
        "wallet", "invoice", "billing", "support", "suspended", "unlock",
    }
)

# fuzzy matching guards: too-short labels make edit distance meaningless
MIN_FUZZY_LABEL = 5
MIN_DIST2_BRAND = 6

_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")


def _result(
    check_id: str,
    name: str,
    max_points: int,
    explanation: str,
    *,
    triggered: bool,
    points: int | None = None,
    evidence: str | None = None,
) -> CheckResult:
    return CheckResult(
        id=check_id,
        name=name,
        category=CheckCategory.LEXICAL,
        status=CheckStatus.TRIGGERED if triggered else CheckStatus.PASSED,
        points=(points if points is not None else max_points) if triggered else 0,
        max_points=max_points,
        evidence=evidence if triggered else None,
        explanation=explanation,
    )


def levenshtein(a: str, b: str) -> int:
    """Classic dynamic-programming edit distance (insert/delete/substitute)."""
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ch_a in enumerate(a, start=1):
        current = [i]
        for j, ch_b in enumerate(b, start=1):
            current.append(
                min(
                    previous[j] + 1,  # deletion
                    current[j - 1] + 1,  # insertion
                    previous[j - 1] + (ch_a != ch_b),  # substitution
                )
            )
        previous = current
    return previous[-1]


def skeleton(text: str) -> str:
    """Reduce text to an ASCII look-alike skeleton for confusable comparison."""
    out: list[str] = []
    for ch in unicodedata.normalize("NFKD", text.lower()):
        if unicodedata.combining(ch):
            continue
        out.append(CONFUSABLES.get(ch, ch))
    return "".join(out)


def _decode_punycode_label(label: str) -> str:
    try:
        return label[4:].encode("ascii").decode("punycode")
    except (UnicodeError, ValueError):
        return label


def check_punycode_homoglyph(url: ValidatedURL) -> CheckResult:
    explanation = (
        "Internationalized domain names can use non-Latin characters that "
        "render identically to Latin ones — 'pаypаl.com' with Cyrillic а is "
        "a different domain from paypal.com but looks the same in the "
        "address bar."
    )
    labels = url.host.split(".")
    decoded = [
        _decode_punycode_label(lb) if lb.startswith("xn--") else lb for lb in labels
    ]
    is_idn = any(lb.startswith("xn--") for lb in labels) or any(
        ord(ch) > 127 for ch in url.host
    )
    if not is_idn:
        return _result(
            "punycode_homoglyph", "Look-alike characters", 25, explanation, triggered=False
        )

    decoded_host = ".".join(decoded)
    domain_skeleton = skeleton(extract(decoded_host).domain)
    for brand in sorted(BRAND_LABELS):
        if domain_skeleton == brand:
            return _result(
                "punycode_homoglyph",
                "Look-alike characters",
                25,
                explanation,
                triggered=True,
                points=25,
                evidence=(
                    f"Domain '{decoded_host}' uses characters that make it "
                    f"visually identical to the brand '{brand}'"
                ),
            )
    return _result(
        "punycode_homoglyph",
        "Look-alike characters",
        25,
        explanation,
        triggered=True,
        points=20,
        evidence=(
            f"Domain uses internationalized characters ('{decoded_host}'); "
            "these are legitimate for non-English sites but are also a "
            "common impersonation vector"
        ),
    )


def check_typosquatting(url: ValidatedURL) -> CheckResult:
    explanation = (
        "Attackers register domains one or two keystrokes away from real "
        "brands (paypa1.com), or hide a real brand inside the subdomain "
        "(paypal.com.evil.tk) so the address starts with a trusted name."
    )
    ext = extract(url.host)
    registrable = registrable_domain(url.host)

    if registrable in BRAND_DOMAINS:
        return _result(
            "typosquatting", "Look-alike domain", 25, explanation, triggered=False
        )

    best_points = 0
    evidence = ""

    label = ext.domain.lower()
    if len(label) >= MIN_FUZZY_LABEL:
        for brand_domain in sorted(BRAND_DOMAINS):
            brand = brand_domain.split(".")[0]
            if len(brand) < MIN_FUZZY_LABEL:
                continue
            distance = levenshtein(label, brand)
            if distance == 1 and best_points < 25:
                best_points = 25
                evidence = f"'{label}' is 1 edit away from '{brand}' ({brand_domain})"
            elif distance == 2 and len(brand) >= MIN_DIST2_BRAND and best_points < 15:
                best_points = 15
                evidence = f"'{label}' is 2 edits away from '{brand}' ({brand_domain})"

    subdomain = ext.subdomain.lower()
    if subdomain and best_points < 20:
        sub_labels = set(subdomain.split("."))
        for brand_domain in sorted(BRAND_DOMAINS):
            brand = brand_domain.split(".")[0]
            if brand_domain in subdomain or brand in sub_labels:
                best_points = 20
                evidence = (
                    f"The trusted name '{brand}' appears in the subdomain, but "
                    f"the real destination is '{registrable or url.host}'"
                )
                break

    return _result(
        "typosquatting",
        "Look-alike domain",
        25,
        explanation,
        triggered=best_points > 0,
        points=best_points,
        evidence=evidence or None,
    )


def check_suspicious_tld(url: ValidatedURL) -> CheckResult:
    suffix = extract(url.host).suffix.lower()
    last = suffix.split(".")[-1] if suffix else ""
    return _result(
        "suspicious_tld",
        "High-abuse domain ending",
        10,
        "Some domain endings are free or near-free to register and appear "
        "in phishing campaigns far out of proportion to legitimate use. "
        "A weak signal by itself, weighted accordingly.",
        triggered=last in SUSPICIOUS_TLDS,
        evidence=f".{last} domains have a documented history of abuse",
    )


def check_url_shortener(url: ValidatedURL) -> CheckResult:
    registrable = registrable_domain(url.host)
    return _result(
        "url_shortener",
        "Shortened link hides destination",
        12,
        "Shorteners are legitimate services, but the visible link tells you "
        "nothing about where it leads — every other safety signal is hidden "
        "behind the redirect.",
        triggered=registrable in SHORTENER_DOMAINS,
        evidence=f"'{registrable}' is a URL shortening service",
    )


def check_keyword_bait(url: ValidatedURL) -> CheckResult:
    explanation = (
        "Words like 'login', 'verify', and 'secure' next to a brand name on "
        "a domain that brand does not own is the classic phishing lure "
        "pattern."
    )
    registrable = registrable_domain(url.host)
    if registrable in BRAND_DOMAINS:
        # 'paypal.com/login' is just PayPal's login page
        return _result("keyword_bait", "Phishing lure keywords", 12, explanation, triggered=False)

    text = f"{url.host} {url.parts.path}".lower()
    tokens = {t for t in _TOKEN_SPLIT.split(text) if t}
    bait = sorted(tokens & BAIT_TOKENS)
    if not bait:
        return _result("keyword_bait", "Phishing lure keywords", 12, explanation, triggered=False)

    brands = sorted(tokens & BRAND_LABELS)
    if brands:
        return _result(
            "keyword_bait",
            "Phishing lure keywords",
            12,
            explanation,
            triggered=True,
            points=12,
            evidence=(
                f"Lure words {', '.join(bait)} appear alongside the brand "
                f"'{brands[0]}' on a domain that is not {brands[0]}"
            ),
        )
    return _result(
        "keyword_bait",
        "Phishing lure keywords",
        12,
        explanation,
        triggered=True,
        points=6,
        evidence=f"Lure words in URL: {', '.join(bait)}",
    )


LEXICAL_CHECKS = [
    check_punycode_homoglyph,
    check_typosquatting,
    check_suspicious_tld,
    check_url_shortener,
    check_keyword_bait,
]
