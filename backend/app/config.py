"""Runtime configuration, sourced from environment variables (or .env locally)."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    google_safe_browsing_api_key: str = ""
    # Comma-separated list of origins allowed to call the API.
    # Empty by default — no CORS unless explicitly configured for prod.
    # In development set ALLOWED_ORIGINS=localhost dev origins as needed.
    allowed_origins: str = ""
    rate_limit_per_minute: int = 10
    # Serve /docs, /redoc, /openapi.json (default off for production)
    expose_api_docs: bool = False
    # Walk redirect chains over an IP-pinned transport (default). Disable
    # only when a shared/mockable http client is preferred, e.g. in tests
    # whose mocks patch the httpcore layer the pinned transport bypasses.
    pin_redirect_fetches: bool = True
    # Fetch RDAP over the same IP-pinned transport (default). Disable for the
    # same mocking reasons as pin_redirect_fetches.
    pin_rdap_fetches: bool = True
    # Reject HTTP redirects that originate from HTTPS (prevents downgrade attacks).
    allow_http_redirect_from_https: bool = False

    @property
    def origins_list(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
