from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.analyzer import analyze
from app.config import get_settings
from app.models import AnalysisResponse, CheckRequest
from app.rate_limit import RateLimiter
from app.validation import URLValidationError

MAX_BODY_BYTES = 4096


def client_ip(request: Request) -> str:
    # Render terminates TLS at a proxy; the client is the first hop in
    # X-Forwarded-For. Trust that header only when the proxy's https signal
    # is present — otherwise a client can forge it to dodge the rate limit.
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded and request.headers.get("x-forwarded-proto") == "https":
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
        docs_url="/docs" if settings.expose_api_docs else None,
        redoc_url="/redoc" if settings.expose_api_docs else None,
        openapi_url="/openapi.json" if settings.expose_api_docs else None,
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.origins_list,
        allow_methods=["GET", "POST"],
        allow_headers=["content-type"],
    )
    limiter = RateLimiter(limit=settings.rate_limit_per_minute)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        # Reject oversized bodies before they are parsed. The URL field is
        # capped at 2048 by the model; this stops a megabyte of JSON from
        # ever reaching the parser. Chunked bodies without a Content-Length
        # header are not covered by this early gate.
        content_length = request.headers.get("content-length")
        if content_length and content_length.isdigit() and int(content_length) > MAX_BODY_BYTES:
            return JSONResponse(
                status_code=413,
                content={
                    "detail": {
                        "code": "BODY_TOO_LARGE",
                        "message": f"Request body exceeds {MAX_BODY_BYTES} bytes.",
                    }
                },
            )
        response = await call_next(request)
        # Scanned URLs are echoed back; keep them out of caches and keep the
        # API surface boring for browsers.
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        return response

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
                redirect_http=(
                    None if settings.pin_redirect_fetches else request.app.state.http
                ),
            )
        except URLValidationError as exc:
            raise HTTPException(
                status_code=400, detail={"code": exc.code, "message": exc.message}
            ) from exc

    return app


app = create_app()
