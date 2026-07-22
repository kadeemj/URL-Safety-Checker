from fastapi import FastAPI


def create_app() -> FastAPI:
    app = FastAPI(
        title="URL Safety Checker API",
        description="Hybrid heuristic + threat-intelligence analysis of URLs.",
        version="0.1.0",
    )

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
