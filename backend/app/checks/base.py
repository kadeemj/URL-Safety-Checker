"""Shared result types for all URL checks.

Every check — heuristic or network-backed — returns a CheckResult. Points are
penalties: a triggered check adds its points to the risk score. A check that
cannot run (timeout, missing API key) reports UNAVAILABLE and contributes
nothing, so the score never punishes a URL for our own outages.
"""

from enum import StrEnum

from pydantic import BaseModel, Field


class CheckStatus(StrEnum):
    PASSED = "passed"
    TRIGGERED = "triggered"
    UNAVAILABLE = "unavailable"
    INFO = "info"


class CheckCategory(StrEnum):
    STRUCTURE = "structure"
    LEXICAL = "lexical"
    REPUTATION = "reputation"
    INFRASTRUCTURE = "infrastructure"


class CheckResult(BaseModel):
    id: str
    name: str
    category: CheckCategory
    status: CheckStatus
    points: int = Field(ge=0, description="Penalty points this check contributed")
    max_points: int = Field(ge=0, description="Worst-case penalty for this check")
    evidence: str | None = None
    explanation: str
