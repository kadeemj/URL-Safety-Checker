import assert from "node:assert/strict";
import { test } from "node:test";

import { JSDOM } from "jsdom";


import { readFile } from "node:fs/promises";

const html = await readFile(new URL("../index.html", import.meta.url), "utf8");
const appSource = await readFile(new URL("../js/app.js", import.meta.url), "utf8");
const configSource = await readFile(
  new URL("../js/config.js", import.meta.url),
  "utf8",
);


test("report is built with textContent, never innerHTML", () => {
  assert.doesNotMatch(appSource, /\.innerHTML\s*=/);
  assert.match(appSource, /textContent/);
});


test("API base URL points at localhost only in local development", () => {
  const evaluate = new Function(
    "window",
    `${configSource}; return API_BASE_URL;`,
  );
  const localDom = new JSDOM("<html></html>", {
    url: "http://localhost:3000/",
    runScripts: "outside-only",
  });
  assert.equal(
    evaluate(localDom.window),
    "http://localhost:8000",
  );

  const prodDom = new JSDOM("<html></html>", {
    url: "https://kadeemj.github.io/URL-Safety-Checker/",
    runScripts: "outside-only",
  });
  assert.equal(
    evaluate(prodDom.window),
    "https://url-safety-checker.onrender.com",
  );
});


test("submitting a dangerous URL renders the verdict and score", async () => {
  const dom = new JSDOM(html, {
    url: "http://localhost:3000/",
    runScripts: "dangerously",
    pretendToBeVisual: true,
  });
  const { window } = dom;
  const { document } = window;
  const payload = {
    submitted_url: "http://paypal.com.evil.tk/secure/login",
    normalized_url: "http://paypal.com.evil.tk/secure/login",
    analyzed_at: "2026-08-19T12:00:00Z",
    duration_ms: 100,
    score: 78,
    verdict: "dangerous",
    confidence: "full",
    safe_browsing: { status: "clear", threats: [] },
    checks: [
      {
        id: "typosquatting",
        name: "Look-alike domain",
        category: "lexical",
        status: "triggered",
        points: 25,
        max_points: 25,
        evidence: "evidence",
        explanation: "explanation",
      },
    ],
  };

  window.fetch = async (url) => {
    if (String(url).includes("/healthz")) {
      return { ok: true, json: async () => ({}) };
    }
    return { ok: true, json: async () => payload };
  };

  const configScript = document.createElement("script");
  configScript.textContent = configSource;
  document.body.append(configScript);

  const appScript = document.createElement("script");
  appScript.textContent = appSource;
  document.body.append(appScript);

  document.getElementById("url-input").value =
    "http://paypal.com.evil.tk/secure/login";
  document.getElementById("check-form").dispatchEvent(
    new window.Event("submit", { bubbles: true, cancelable: true }),
  );

  await new Promise((resolve) => setTimeout(resolve, 0));

  assert.equal(
    document.querySelector(".verdict-banner .verdict-text h2").textContent,
    "Dangerous",
  );
  assert.equal(
    document.querySelector(".score-number").textContent,
    "78",
  );
  assert.equal(
    document.querySelector(".scanned-url").textContent,
    "http://paypal.com.evil.tk/secure/login",
  );
});
