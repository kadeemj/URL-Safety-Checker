from fastapi import FastAPI, HTTPException

from app.analyzer import analyze
from app.models import AnalysisResponse, CheckRequest
from app.validation import URLValidationError


def create_app() -> FastAPI:
    app = FastAPI(
        title="URL Safety Checker API",
        description="Hybrid heuristic + threat-intelligence analysis of URLs.",
        version="0.1.0",
    )

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/v1/check", response_model=AnalysisResponse)
    async def check_url(request: CheckRequest) -> AnalysisResponse:
        try:
            return await analyze(request.url)
        except URLValidationError as exc:
            raise HTTPException(
                status_code=400, detail={"code": exc.code, "message": exc.message}
            ) from exc

    return app


app = create_app()
