// Backend base URL. Local development talks to a local uvicorn; the
// deployed GitHub Pages site talks to the Render service.
// After deploying to Render, replace the production URL below.
// NOTE: keep this origin in sync with the connect-src directive in the
// Content-Security-Policy meta tag of index.html.
const API_BASE_URL = ["localhost", "127.0.0.1"].includes(window.location.hostname)
  ? "http://localhost:8000"
  : "https://url-safety-checker.onrender.com";
