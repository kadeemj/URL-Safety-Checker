"""Risk aggregation: per-check penalties -> score, verdict, confidence.

Model: score = min(100, sum of triggered penalties). Deliberately simple —
every point in the final score traces back to one named check, so the whole
model is auditable at a glance.

Weight reference (max penalty per check):

    userinfo_trick        25    typosquatting        25
    punycode_homoglyph    25    ip_address_host      20
    domain_age            20    redirect_chain       15
    url_length_entropy    12    url_shortener        12
    keyword_bait          12    https_scheme         10
    suspicious_tld        10    nonstandard_port      8
    excessive_subdomains   8    domain_lexical        8

Safe Browsing is not a weighted vote — a confirmed listing overrides:
verdict becomes 'dangerous' and the score floors at 95. A *clear* result
subtracts nothing (absence of evidence is not evidence of absence).
"""

from dataclasses import dataclass

from app.checks.base import CheckResult, CheckStatus
from app.models import Confidence, SafeBrowsingResult, Verdict

SUSPICIOUS_THRESHOLD = 25
DANGEROUS_THRESHOLD = 60
SAFE_BROWSING_FLOOR = 95


@dataclass(frozen=True)
class ScoreSummary:
    score: int
    verdict: Verdict
    confidence: Confidence


def aggregate(checks: list[CheckResult], safe_browsing: SafeBrowsingResult) -> ScoreSummary:
    score = min(100, sum(c.points for c in checks if c.status == CheckStatus.TRIGGERED))

    if safe_browsing.status == "hit":
        score = max(score, SAFE_BROWSING_FLOOR)
        verdict: Verdict = "dangerous"
    elif score >= DANGEROUS_THRESHOLD:
        verdict = "dangerous"
    elif score >= SUSPICIOUS_THRESHOLD:
        verdict = "suspicious"
    else:
        verdict = "safe"

    any_unavailable = safe_browsing.status == "unavailable" or any(
        c.status == CheckStatus.UNAVAILABLE for c in checks
    )
    confidence: Confidence = "partial" if any_unavailable else "full"

    return ScoreSummary(score=score, verdict=verdict, confidence=confidence)
