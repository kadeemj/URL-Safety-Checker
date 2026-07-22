from app.checks.base import CheckCategory, CheckResult, CheckStatus
from app.models import SafeBrowsingResult
from app.scoring import aggregate


def check(points: int, status: CheckStatus = CheckStatus.TRIGGERED) -> CheckResult:
    return CheckResult(
        id="synthetic",
        name="Synthetic",
        category=CheckCategory.STRUCTURE,
        status=status,
        points=points,
        max_points=25,
        explanation="test",
    )


CLEAR = SafeBrowsingResult(status="clear", threats=[])
HIT = SafeBrowsingResult(status="hit", threats=["SOCIAL_ENGINEERING"])
SB_DOWN = SafeBrowsingResult(status="unavailable", threats=[])


class TestScore:
    def test_sum_of_triggered_points(self) -> None:
        summary = aggregate([check(10), check(8)], CLEAR)
        assert summary.score == 18

    def test_capped_at_100(self) -> None:
        summary = aggregate([check(25)] * 6, CLEAR)
        assert summary.score == 100

    def test_unavailable_checks_contribute_nothing(self) -> None:
        summary = aggregate([check(10), check(0, CheckStatus.UNAVAILABLE)], CLEAR)
        assert summary.score == 10


class TestVerdictTiers:
    def test_24_is_safe(self) -> None:
        assert aggregate([check(24)], CLEAR).verdict == "safe"

    def test_25_is_suspicious(self) -> None:
        assert aggregate([check(25)], CLEAR).verdict == "suspicious"

    def test_59_is_suspicious(self) -> None:
        assert aggregate([check(25), check(25), check(9)], CLEAR).verdict == "suspicious"

    def test_60_is_dangerous(self) -> None:
        assert aggregate([check(25), check(25), check(10)], CLEAR).verdict == "dangerous"


class TestSafeBrowsingOverride:
    def test_hit_forces_dangerous_and_floor_95(self) -> None:
        summary = aggregate([check(10)], HIT)
        assert summary.verdict == "dangerous"
        assert summary.score == 95

    def test_hit_keeps_higher_heuristic_score(self) -> None:
        summary = aggregate([check(25)] * 4, HIT)  # heuristics alone = 100
        assert summary.score == 100

    def test_clear_subtracts_nothing(self) -> None:
        assert aggregate([check(30)], CLEAR).score == 30


class TestConfidence:
    def test_full_when_everything_resolved(self) -> None:
        assert aggregate([check(10)], CLEAR).confidence == "full"

    def test_partial_when_a_check_is_unavailable(self) -> None:
        summary = aggregate([check(0, CheckStatus.UNAVAILABLE)], CLEAR)
        assert summary.confidence == "partial"

    def test_partial_when_safe_browsing_is_down(self) -> None:
        assert aggregate([check(10)], SB_DOWN).confidence == "partial"
