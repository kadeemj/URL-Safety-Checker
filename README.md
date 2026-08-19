# URL Safety Checker

[![CI](https://github.com/kadeemj/URL-Safety-Checker/actions/workflows/ci.yml/badge.svg)](https://github.com/kadeemj/URL-Safety-Checker/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Paste a link, get a verdict — and the reasoning behind it.

A hybrid URL analysis tool: **14 locally-computed security heuristics** plus a
**Google Safe Browsing** reputation lookup, combined into an explainable 0–100
risk score. Every point in the final score traces back to one named check with
plain-English evidence, so the report teaches you *why* a link is risky instead
of handing down an opaque verdict.

**Live demo:** https://kadeemj.github.io/URL-Safety-Checker/

## Architecture

```
┌─────────────────────┐  POST /api/v1/check   ┌──────────────────────────┐
│  GitHub Pages       │ ────────────────────► │  FastAPI on Render        │
│  (static frontend,  │                       │                           │
│  vanilla JS)        │ ◄──────────────────── │  1. validate + SSRF guard │
└─────────────────────┘   JSON report card    │  2. 12 local heuristics   │
                                              │  3. concurrently:         │
                                              │     · Google Safe Browsing│
                                              │     · RDAP domain age     │
                                              │     · redirect chain walk │
                                              │  4. score + verdict       │
                                              └──────────────────────────┘
```

- **Frontend** (`docs/`): plain HTML/CSS/JS, no framework, no build step.
  Served by GitHub Pages. All API-derived strings are rendered with
  `textContent` — the analyzed URL is attacker-controlled input and is never
  interpolated into HTML.
- **Backend** (`backend/`): FastAPI + httpx. The Safe Browsing API key lives
  only in the server environment. CORS is restricted to the Pages origin, and
  a per-IP sliding-window rate limit protects the public endpoint.

## The checks

| Check | Signal | Max points |
|---|---|---|
| Deceptive username-in-URL | `https://paypal.com@evil.example` visits evil.example | 25 |
| Look-alike domain (typosquatting) | Levenshtein distance to 55 top brands; brand-in-subdomain | 25 |
| Look-alike characters (homoglyphs) | Punycode/IDN skeleton matches a brand (`pаypаl` ≠ `paypal`) | 25 |
| Raw IP address host | No domain, no accountability | 20 |
| Domain age (RDAP) | Registered <30 days (+20) or <180 days (+10) | 20 |
| Redirect chain | Length, shortener hops, redirect into private address space | 15 |
| Unusually long / random URL | Length tiers + Shannon entropy of path/query | 12 |
| URL shortener | Destination is hidden — an opacity penalty, not an accusation | 12 |
| Phishing lure keywords | `login`/`verify`/`secure` + a brand token on a foreign domain | 12 |
| Unencrypted (http) | Credential pages belong on HTTPS | 10 |
| High-abuse TLD | `.tk`, `.zip`, `.top`, … weighted low: weak signal alone | 10 |
| Non-standard port | Ad-hoc infrastructure | 8 |
| Excessive subdomains | `login.secure.account.verify.example.com` | 8 |
| Machine-generated domain | Hyphen/digit-dense registrable domains | 8 |
| **Google Safe Browsing** | Confirmed listing **overrides everything** (see below) | — |

**Scoring:** `score = min(100, Σ triggered penalties)` →
0–24 **Safe** · 25–59 **Suspicious** · 60–100 **Dangerous**.

Two asymmetries are deliberate:

- A Safe Browsing **hit** forces the verdict to Dangerous and floors the score
  at 95 — Google has confirmed active abuse; heuristics can't argue it down.
- A Safe Browsing **clear does not subtract points**. Absence of evidence is
  not evidence of absence: brand-new phishing pages haven't been catalogued yet.

Checks that cannot run (RDAP timeout, missing API key) report as
`unavailable`, contribute zero points, and downgrade the response's
`confidence` field to `partial` — the tool never punishes a URL for our own
outages, and never pretends a lookup happened when it didn't.

## Threat model notes

The interesting security problem here is that the service **fetches
attacker-supplied URLs** (redirect walking), which is a textbook SSRF vector.
`backend/app/validation.py` implements the guard:

- scheme allow-list (http/https), length cap, blocked hostname suffixes
  (`.local`, `.internal`, `.onion`, localhost)
- literal-IP screening including integer-encoded forms (`http://2130706433/`
  is `127.0.0.1`)
- DNS resolution check: the hostname is resolved and rejected if **any**
  address is non-global (blocks DNS-rebinding into `169.254.169.254` etc.)
- the guard is **re-run on every redirect hop**, and credentials are stripped
  from URLs before any outbound request

Other hardening: origin-restricted CORS, per-IP rate limiting
(`X-Forwarded-For`-aware behind Render's proxy), non-root Docker image,
no persistence of submitted URLs.

### Hardening details

- **IP-pinned outbound transport** (`app/transport.py`): the redirect walk
  resolves each hop, screens every address for publicness, and connects to
  the *screened address itself* — httpx never re-resolves the hostname, so a
  DNS answer swapped after validation cannot redirect the fetch into private
  space. TLS is still verified against the real hostname. Per-walk cache
  TTL of 60 s; response bodies capped at 1 MiB.
- **Security headers + `Cache-Control: no-store`** on every API response;
  scanned URLs are echoed back and must not linger in shared caches.
- **CSP on the frontend**: `script-src`/`style-src`/`img-src` restricted to
  `'self'`, `connect-src` limited to the API origin, `frame-ancestors`,
  `base-uri` and `form-action` locked down (GitHub Pages cannot set headers,
  so the policy ships as a meta tag).
- **Request body cap**: `Content-Length` over 4 KB is rejected with 413
  before JSON parsing (the URL field itself is capped at 2048 chars).
- **DNS timeouts**: hostname resolution is bounded (5 s) so a hung resolver
  cannot stall a request.
- **Rate limiter memory bound**: at most 10,000 distinct IPs are tracked;
  the longest-idle entry is evicted beyond that. `X-Forwarded-For` is
  honored only when the proxy's https signal is present, so the header
  cannot be forged to dodge the limit on a proxy-less deployment.
- **API docs disabled by default** (`EXPOSE_API_DOCS=false`); `/docs` and
  `/openapi.json` are 404s in production.
- **Redirect hops are IP-pinned** (`PIN_REDIRECT_FETCHES=true`): each hop is
  resolved, screened, and connected *to the screened address*, so a second,
  unchecked resolution cannot slip past the private-address guard.

## Run it locally

```bash
# backend — Python 3.12+
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env        # optionally add your Safe Browsing key
uvicorn app.main:app --reload            # http://localhost:8000

# frontend — any static server
cd ../docs
python3 -m http.server 3000              # http://localhost:3000
```

Works without any API key — the Safe Browsing check just reports
`unavailable` and the 14 heuristics still run.

```bash
# tests + lint
cd backend
pytest          # 139 tests, all external calls mocked (respx)
ruff check .
```

## Deploy

1. **Backend → Render:** "New +" → Blueprint → point at this repo
   (`render.yaml` configures everything). Set `GOOGLE_SAFE_BROWSING_API_KEY`
   in the dashboard.
2. **Frontend → GitHub Pages:** repo Settings → Pages → deploy from branch
   `main`, folder `/docs`.
3. Point `docs/js/config.js` at your Render URL.

## Limitations (known and accepted)

- The rate limiter is in-memory — correct on Render's single-instance free
  tier, undercounts on a multi-instance deployment.
- The brand list is ~55 domains; typosquats of unlisted brands won't match.
- Render's free tier sleeps when idle; the first scan of the day takes
  ~30–60 s (the UI explains this while it waits).
- A "Safe" verdict means *no signals found*, not *proven safe*. Advisory
  tool, not an oracle.
- The domain-age check (`app/checks/domain_age.py`) fetches `rdap.org` with
  `follow_redirects=True` over the IP-pinned transport, so its bootstrap
  redirector and registry targets are resolved, screened, and connected to
  the screened address.

## License

MIT
