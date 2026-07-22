"""Pydantic models defining the public API contract."""

from typing import Literal

from pydantic import BaseModel, Field

from app.checks.base import CheckResult

Verdict = Literal["safe", "suspicious", "dangerous"]
Confidence = Literal["full", "partial"]


class CheckRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class SafeBrowsingResult(BaseModel):
    status: Literal["clear", "hit", "unavailable"]
    threats: list[str] = []


class AnalysisResponse(BaseModel):
    submitted_url: str
    normalized_url: str
    analyzed_at: str
    duration_ms: int
    score: int = Field(ge=0, le=100)
    verdict: Verdict
    confidence: Confidence
    safe_browsing: SafeBrowsingResult
    checks: list[CheckResult]


ErrorCode = Literal[
    "INVALID_SCHEME", "PRIVATE_HOST", "UNRESOLVABLE_HOST", "URL_TOO_LONG", "INVALID_URL"
]


class ErrorDetail(BaseModel):
    code: ErrorCode
    message: str
