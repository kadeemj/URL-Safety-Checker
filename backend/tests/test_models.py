from app.checks.base import CheckCategory, CheckResult, CheckStatus
from app.models import AnalysisResponse, SafeBrowsingResult


def make_check(**overrides) -> CheckResult:
    defaults = {
        "id": "typosquatting",
        "name": "Look-alike domain",
        "category": CheckCategory.LEXICAL,
        "status": CheckStatus.TRIGGERED,
        "points": 25,
        "max_points": 25,
        "evidence": "'paypa1' is 1 edit away from 'paypal'",
        "explanation": "Attackers register domains one keystroke from real brands.",
    }
    defaults.update(overrides)
    return CheckResult(**defaults)


def test_check_result_serializes_enums_as_strings() -> None:
    data = make_check().model_dump()
    assert data["category"] == "lexical"
    assert data["status"] == "triggered"
    assert data["points"] == 25


def test_passed_check_carries_zero_points() -> None:
    check = make_check(status=CheckStatus.PASSED, points=0, evidence=None)
    data = check.model_dump()
    assert data["points"] == 0
    assert data["evidence"] is None


def test_analysis_response_shape() -> None:
    response = AnalysisResponse(
        submitted_url="http://evil.example/login",
        normalized_url="http://evil.example/login",
        analyzed_at="2026-07-22T21:00:00Z",
        duration_ms=812,
        score=78,
        verdict="dangerous",
        confidence="full",
        safe_browsing=SafeBrowsingResult(status="clear", threats=[]),
        checks=[make_check()],
    )
    data = response.model_dump()
    assert data["verdict"] == "dangerous"
    assert data["safe_browsing"]["status"] == "clear"
    assert len(data["checks"]) == 1
