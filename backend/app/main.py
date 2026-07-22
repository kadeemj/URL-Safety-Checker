from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

from app.analyzer import analyze
from app.config import get_settings
from app.models import AnalysisResponse, CheckRequest
from app.rate_limit import RateLimiter
from app.validation import URLValidationError


def client_ip(request: Request) -> str:
    # Render terminates TLS at a proxy; the client is the first hop in
    # X-Forwarded-For. Locally there is no proxy and we use the socket peer.
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # one pooled client for the app's lifetime; never follows redirects
    # implicitly — the redirect check walks hops itself, guarded per hop
    app.state.http = httpx.AsyncClient(follow_redirects=False)
    yield
    await app.state.http.aclose()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="URL Safety Checker API",
        description="Hybrid heuristic + threat-intelligence analysis of URLs.",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.origins_list,
        allow_methods=["GET", "POST"],
        allow_headers=["content-type"],
    )
    limiter = RateLimiter(limit=settings.rate_limit_per_minute)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/v1/check", response_model=AnalysisResponse)
    async def check_url(request: Request, body: CheckRequest) -> AnalysisResponse:
        settings = get_settings()
        retry_after = limiter.check(client_ip(request))
        if retry_after is not None:
            raise HTTPException(
                status_code=429,
                detail={"code": "RATE_LIMITED", "message": "Too many requests."},
                headers={"Retry-After": str(int(retry_after) + 1)},
            )
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
