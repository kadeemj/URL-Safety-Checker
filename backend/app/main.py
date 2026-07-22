from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException, Request

from app.analyzer import analyze
from app.config import get_settings
from app.models import AnalysisResponse, CheckRequest
from app.validation import URLValidationError


@asynccontextmanager
async def lifespan(app: FastAPI):
    # one pooled client for the app's lifetime; never follows redirects
    # implicitly — the redirect check walks hops itself, guarded per hop
    app.state.http = httpx.AsyncClient(follow_redirects=False)
    yield
    await app.state.http.aclose()


def create_app() -> FastAPI:
    app = FastAPI(
        title="URL Safety Checker API",
        description="Hybrid heuristic + threat-intelligence analysis of URLs.",
        version="0.1.0",
        lifespan=lifespan,
    )

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/v1/check", response_model=AnalysisResponse)
    async def check_url(request: Request, body: CheckRequest) -> AnalysisResponse:
        settings = get_settings()
        try:
            return await analyze(
                body.url,
                http=request.app.state.http,
                gsb_api_key=settings.google_safe_browsing_api_key,
            )
        except URLValidationError as exc:
            raise HTTPException(
                status_code=400, detail={"code": exc.code, "message": exc.message}
            ) from exc

    return app


app = create_app()
