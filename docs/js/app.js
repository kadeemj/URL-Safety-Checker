"use strict";

// ---------------------------------------------------------------------------
// Security note: every string that came from the API response (or from the
// user) is rendered with textContent / createElement — never innerHTML.
// The analyzed URL is attacker-controlled input; treat it that way.
// ---------------------------------------------------------------------------

const form = document.getElementById("check-form");
const input = document.getElementById("url-input");
const submitBtn = document.getElementById("submit-btn");
const statusEl = document.getElementById("status");
const reportEl = document.getElementById("report");

const REQUEST_TIMEOUT_MS = 90_000;
const COLD_START_HINT_MS = 8_000;

const VERDICT_COPY = {
  safe: {
    label: "Looks safe",
    detail: "No meaningful risk signals were found. Stay alert anyway — no scanner sees everything.",
  },
  suspicious: {
    label: "Suspicious",
    detail: "Several risk signals triggered. Do not enter credentials or download files from this link.",
  },
  dangerous: {
    label: "Dangerous",
    detail: "Strong indicators of phishing or malware. Do not visit this link.",
  },
};

const CATEGORY_LABELS = {
  reputation: "Threat intelligence",
  lexical: "Impersonation & wording",
  structure: "URL structure",
  infrastructure: "Infrastructure behavior",
};

const ERROR_COPY = {
  INVALID_SCHEME: "Only http:// and https:// links can be analyzed.",
  PRIVATE_HOST: "That address points at a private or internal network, which this tool won't probe.",
  UNRESOLVABLE_HOST: "That domain doesn't resolve — it may be mistyped, or already taken down.",
  URL_TOO_LONG: "That URL is too long to analyze (2048 character limit).",
  INVALID_URL: "That doesn't look like a valid URL. Include the scheme, e.g. https://example.com.",
};

// Wake the free-tier backend as soon as the page loads (fire-and-forget).
fetch(`${API_BASE_URL}/healthz`).catch(() => {});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const url = input.value.trim();
  if (!url) return;

  clearChildren(reportEl);
  reportEl.classList.add("hidden");
  setBusy(true);
  showStatus("spinner", "Analyzing URL…");

  const coldStartTimer = setTimeout(() => {
    showStatus(
      "spinner",
      "Waking the analysis server — free hosting sleeps when idle. This can take 30–60 seconds."
    );
  }, COLD_START_HINT_MS);

  const controller = new AbortController();
  const abortTimer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/check`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });

    if (response.status === 429) {
      showStatus("error", "Too many requests — give it a minute and try again.");
      return;
    }
    if (response.status === 400) {
      const payload = await response.json().catch(() => null);
      const code = payload?.detail?.code;
      showStatus("error", ERROR_COPY[code] || "That URL can't be analyzed.");
      return;
    }
    if (!response.ok) {
      showStatus("error", `The analysis service returned an error (HTTP ${response.status}).`);
      return;
    }

    const data = await response.json();
    hideStatus();
    renderReport(data);
  } catch (err) {
    showStatus(
      "error",
      err.name === "AbortError"
        ? "The analysis timed out. The free-tier server may be overloaded — try again shortly."
        : "Could not reach the analysis service. Check your connection and try again."
    );
  } finally {
    clearTimeout(coldStartTimer);
    clearTimeout(abortTimer);
    setBusy(false);
  }
});

function renderReport(data) {
  clearChildren(reportEl);

  // --- verdict banner -------------------------------------------------
  const banner = el("div", `verdict-banner verdict-${data.verdict}`);
  const scoreWrap = el("div", "score-wrap");
  scoreWrap.append(
    el("div", "score-number", String(data.score)),
    el("div", "score-label", "risk / 100")
  );
  const verdictText = el("div", "verdict-text");
  const copy = VERDICT_COPY[data.verdict] || { label: data.verdict, detail: "" };
  verdictText.append(el("h2", null, copy.label), el("p", null, copy.detail));
  banner.append(scoreWrap, verdictText);

  const meter = el("div", "meter");
  meter.setAttribute("role", "img");
  meter.setAttribute("aria-label", `Risk score ${data.score} out of 100`);
  const fill = el("div", `meter-fill verdict-${data.verdict}`);
  fill.style.width = `${data.score}%`;
  meter.append(fill);

  // --- scanned URL + metadata ------------------------------------------
  const meta = el("p", "scan-meta");
  meta.append(
    el("span", "scanned-url", data.submitted_url),
    el(
      "span",
      "scan-facts",
      ` · analyzed in ${data.duration_ms} ms · confidence: ${data.confidence}` +
        (data.confidence === "partial" ? " (some external lookups were unavailable)" : "")
    )
  );

  reportEl.append(banner, meter, meta);

  // --- checks grouped by category, worst-first --------------------------
  const order = ["reputation", "lexical", "structure", "infrastructure"];
  for (const category of order) {
    const checks = data.checks
      .filter((c) => c.category === category)
      .sort((a, b) => b.points - a.points);
    if (!checks.length) continue;

    const triggered = checks.filter((c) => c.status === "triggered");
    const allUnavailable = checks.every((c) => c.status === "unavailable");
    const details = document.createElement("details");
    details.className = "category";
    if (triggered.length) details.open = true;

    let countClass = "category-count clean";
    let countText = "all clear";
    if (triggered.length) {
      countClass = "category-count flagged";
      countText = `${triggered.length} flagged`;
    } else if (allUnavailable) {
      // never imply "clear" when the lookups didn't actually run
      countClass = "category-count muted";
      countText = "unavailable";
    }

    const summary = el("summary");
    summary.append(
      el("span", "category-name", CATEGORY_LABELS[category] || category),
      el("span", countClass, countText)
    );
    details.append(summary);

    for (const check of checks) details.append(renderCheck(check));
    reportEl.append(details);
  }

  reportEl.classList.remove("hidden");
  reportEl.scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderCheck(check) {
  const row = el("div", `check check-${check.status}`);

  const head = el("div", "check-head");
  head.append(
    el("span", "check-status-icon", statusIcon(check.status)),
    el("span", "check-name", check.name),
    el(
      "span",
      "check-points",
      check.status === "triggered" && check.points > 0 ? `+${check.points}` : statusWord(check.status)
    )
  );
  row.append(head);

  if (check.evidence) row.append(el("p", "check-evidence", check.evidence));
  row.append(el("p", "check-explanation", check.explanation));
  return row;
}

function statusIcon(status) {
  return { triggered: "⚠", passed: "✓", unavailable: "–", info: "ℹ" }[status] || "•";
}

function statusWord(status) {
  return { passed: "passed", unavailable: "unavailable", info: "info", triggered: "flagged" }[status] || status;
}

// --- tiny DOM helpers -----------------------------------------------------

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

function clearChildren(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function showStatus(kind, message) {
  clearChildren(statusEl);
  if (kind === "spinner") statusEl.append(el("span", "spinner"));
  statusEl.append(el("span", null, message));
  statusEl.className = `status status-${kind}`;
}

function hideStatus() {
  statusEl.className = "status hidden";
}

function setBusy(busy) {
  submitBtn.disabled = busy;
  submitBtn.textContent = busy ? "Analyzing…" : "Analyze";
}
