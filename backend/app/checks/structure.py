"""Structural checks: signals readable straight off the URL's anatomy."""

import math
from collections import Counter

from app.checks.base import CheckCategory, CheckResult, CheckStatus
from app.domains import domain_label, subdomain_labels
from app.validation import ValidatedURL

LONG_URL = 75
VERY_LONG_URL = 100
ENTROPY_THRESHOLD = 4.2
ENTROPY_MIN_LENGTH = 16
MAX_SUBDOMAIN_LABELS = 3


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
        category=CheckCategory.STRUCTURE,
        status=CheckStatus.TRIGGERED if triggered else CheckStatus.PASSED,
        points=(points if points is not None else max_points) if triggered else 0,
        max_points=max_points,
        evidence=evidence if triggered else None,
        explanation=explanation,
    )


def check_https_scheme(url: ValidatedURL) -> CheckResult:
    return _result(
        "https_scheme",
        "Unencrypted connection",
        10,
        "Legitimate services serve login and account pages over HTTPS. Plain "
        "HTTP exposes everything you type and is common on throwaway phishing "
        "infrastructure.",
        triggered=url.scheme == "http",
        evidence="URL uses http://, not https://",
    )


def check_userinfo_trick(url: ValidatedURL) -> CheckResult:
    username = url.parts.username or ""
    return _result(
        "userinfo_trick",
        "Deceptive username-in-URL",
        25,
        "Anything before an @ in a URL is a username, not the destination. "
        "Attackers exploit this so 'https://paypal.com@evil.example' looks "
        "like PayPal but actually visits evil.example.",
        triggered=url.has_userinfo,
        evidence=f"URL contains credentials part '{username}@' before the real host "
        f"'{url.host}'",
    )


def check_ip_address_host(url: ValidatedURL) -> CheckResult:
    looks_like_ip = url.parts.hostname is not None and (
        url.host.replace(".", "").isdigit() or ":" in url.host
    )
    return _result(
        "ip_address_host",
        "Raw IP address instead of domain",
        20,
        "Legitimate sites use domain names. A raw IP address hides who owns "
        "the server and often points at compromised or short-lived hosts.",
        triggered=looks_like_ip,
        evidence=f"Host is the literal address {url.host}",
    )


def check_nonstandard_port(url: ValidatedURL) -> CheckResult:
    return _result(
        "nonstandard_port",
        "Non-standard port",
        8,
        "Web traffic runs on ports 80 and 443. An explicit unusual port often "
        "means an ad-hoc server rather than production infrastructure.",
        triggered=url.port not in (None, 80, 443),
        evidence=f"URL targets port {url.port}",
    )


def check_excessive_subdomains(url: ValidatedURL) -> CheckResult:
    labels = subdomain_labels(url.host)
    return _result(
        "excessive_subdomains",
        "Excessive subdomain nesting",
        8,
        "Long subdomain chains like login.secure.account.verify.example.com "
        "push a trustworthy-looking word into the visible part of the address "
        "bar while the real domain hides at the end.",
        triggered=len(labels) > MAX_SUBDOMAIN_LABELS,
        evidence=f"{len(labels)} subdomain labels: {'.'.join(labels)}",
    )


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def check_url_length_entropy(url: ValidatedURL) -> CheckResult:
    length = len(url.original)
    points = 0
    notes: list[str] = []

    if length > VERY_LONG_URL:
        points += 8
        notes.append(f"URL is {length} characters long")
    elif length > LONG_URL:
        points += 4
        notes.append(f"URL is {length} characters long")

    tail = url.parts.path + url.parts.query
    entropy = _shannon_entropy(tail) if len(tail) >= ENTROPY_MIN_LENGTH else 0.0
    if entropy > ENTROPY_THRESHOLD:
        points += 4
        notes.append(f"path/query entropy {entropy:.2f} bits/char suggests random tokens")

    return _result(
        "url_length_entropy",
        "Unusually long or random-looking URL",
        12,
        "Phishing links are often stuffed with long random tokens to evade "
        "filters and to give each victim a unique tracking URL.",
        triggered=points > 0,
        points=points,
        evidence="; ".join(notes),
    )


def check_domain_lexical(url: ValidatedURL) -> CheckResult:
    label = domain_label(url.host)
    hyphens = label.count("-")
    digits = sum(ch.isdigit() for ch in label)
    digit_ratio = digits / len(label) if label else 0.0
    triggered = hyphens >= 2 or digit_ratio > 0.30

    reasons: list[str] = []
    if hyphens >= 2:
        reasons.append(f"{hyphens} hyphens in '{label}'")
    if digit_ratio > 0.30:
        reasons.append(f"{digit_ratio:.0%} of '{label}' is digits")

    return _result(
        "domain_lexical",
        "Machine-generated domain pattern",
        8,
        "Domains packed with hyphens or digits are typical of bulk-registered "
        "throwaway infrastructure rather than an established brand.",
        triggered=triggered,
        evidence="; ".join(reasons),
    )


STRUCTURE_CHECKS = [
    check_https_scheme,
    check_userinfo_trick,
    check_ip_address_host,
    check_nonstandard_port,
    check_excessive_subdomains,
    check_url_length_entropy,
    check_domain_lexical,
]
