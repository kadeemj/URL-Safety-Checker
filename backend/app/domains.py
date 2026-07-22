"""Registrable-domain parsing shared by all checks.

Uses tldextract with its bundled Public Suffix List snapshot only
(suffix_list_urls=()) so the service never fetches the PSL at runtime —
no surprise network dependency on cold start, and tests stay offline.
"""

import tldextract

_extract = tldextract.TLDExtract(suffix_list_urls=())


def extract(host: str) -> tldextract.tldextract.ExtractResult:
    return _extract(host)


def registrable_domain(host: str) -> str:
    """'login.paypal.com.evil.co.uk' -> 'evil.co.uk'; '' when host has no known suffix."""
    return extract(host).top_domain_under_public_suffix


def domain_label(host: str) -> str:
    """The label left of the public suffix: 'evil.co.uk' -> 'evil'."""
    return extract(host).domain


def subdomain_labels(host: str) -> list[str]:
    sub = extract(host).subdomain
    return sub.split(".") if sub else []
