// Backend base URL. Local development talks to a local uvicorn; the
// deployed GitHub Pages site talks to the Render service.
// After deploying to Render, replace the production URL below.
const API_BASE_URL = ["localhost", "127.0.0.1"].includes(window.location.hostname)
  ? "http://localhost:8000"
  : "https://url-safety-checker.onrender.com";
