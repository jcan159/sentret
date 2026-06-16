// Sentret web UI — vanilla JS. Consumes the /api/analyse SSE stream and renders
// the structured report. All model/tool output is inserted via textContent or
// created DOM nodes (never innerHTML), so log-derived content cannot inject markup.

"use strict";

const $ = (id) => document.getElementById(id);
const el = (tag, props = {}, ...children) => {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else node.setAttribute(k, v);
  }
  for (const c of children) node.append(c);
  return node;
};

let lastReport = null;
let lastMarkdown = "";

// --- Load server config (non-secret) -------------------------------------
const PROVIDER_META = {
  anthropic: { label: "Claude (Anthropic)" },
  openai: { label: "OpenAI" },
  azure: { label: "Azure AI Foundry" },
};

function modelFor(cfg, provider) {
  if (provider === "openai") return cfg.openaiModel;
  if (provider === "azure") return cfg.azureDeployment || "deployment unset";
  return cfg.anthropicModel;
}

function populateProviders(cfg) {
  const sel = $("provider");
  const available = cfg.available || {};
  const defaultModel = modelFor(cfg, cfg.provider);
  const opts = [el("option", { value: "", text: `Server default — ${cfg.provider} (${defaultModel})` })];
  for (const key of ["anthropic", "openai", "azure"]) {
    const meta = PROVIDER_META[key];
    const has = !!available[key];
    const model = modelFor(cfg, key);
    const text = has ? `${meta.label} · ${model}` : `${meta.label} — no key configured`;
    const props = { value: key, text };
    if (!has) props.disabled = "disabled";
    opts.push(el("option", props));
  }
  sel.replaceChildren(...opts);
  sel.value = ""; // default to the server's auto-detected provider

  const noneAvailable = !available.anthropic && !available.openai && !available.azure;
  $("provider-badge").textContent = noneAvailable
    ? "provider: no API keys configured"
    : `provider: ${cfg.provider} · ${defaultModel}`;
}

fetch("/api/config")
  .then((r) => r.json())
  .then(populateProviders)
  .catch(() => {
    $("provider-badge").textContent = "provider: unavailable";
  });

// --- Mode toggle hides KQL for create mode -------------------------------
$("mode").addEventListener("change", () => {
  $("kql-wrap").style.display = $("mode").value === "create_new_detection" ? "none" : "";
});

// --- Example loader ------------------------------------------------------
$("example").addEventListener("click", () => {
  $("mode").value = "analyse_existing_rule";
  $("kql-wrap").style.display = "";
  $("detection_intent").value =
    "Detect successful sign-ins from countries the user has not previously signed in from.";
  $("workspace_id").value = "00000000-0000-0000-0000-000000000000";
  $("timespan").value = "P7D";
  $("kql").value =
    "SigninLogs\n| where ResultType == 0\n| summarize count() by UserPrincipalName, Location";
});

// --- Build the request payload from the form -----------------------------
function buildPayload() {
  const mode = $("mode").value;
  const request = {
    mode,
    detection_intent: $("detection_intent").value.trim(),
    workspace_id: $("workspace_id").value.trim(),
    timespan: $("timespan").value.trim(),
    allow_query_execution: $("allow_query_execution").checked,
    allow_raw_examples: $("allow_raw_examples").checked,
  };
  if (mode === "analyse_existing_rule") request.kql = $("kql").value.trim();
  const opt = (id, key) => {
    const v = $(id).value.trim();
    if (v) request[key] = v;
  };
  opt("severity_preference", "severity_preference");
  opt("noise_tolerance", "noise_tolerance");
  opt("rule_frequency", "rule_frequency");
  opt("rule_period", "rule_period");

  const overrides = {};
  if ($("provider").value) overrides.provider = $("provider").value;
  if ($("effort").value) overrides.effort = $("effort").value;

  return { request, overrides: Object.keys(overrides).length ? overrides : undefined };
}

// --- UI helpers ----------------------------------------------------------
function resetResults() {
  $("stream").textContent = "";
  $("activity").replaceChildren();
  $("report-card").classList.add("hidden");
  $("report").replaceChildren();
  $("verdict").classList.remove("show");
  $("model-used").textContent = "";
  lastReport = null;
  lastMarkdown = "";
}

function addActivity(text, cls) {
  const node = el("div", { class: "ev" + (cls ? " " + cls : ""), text });
  $("activity").append(node);
  $("activity").scrollTop = $("activity").scrollHeight;
}

function appendStream(text) {
  const s = $("stream");
  s.textContent += text;
  s.scrollTop = s.scrollHeight;
}

// --- Structured-report rendering (DOM only, XSS-safe) ---------------------
function list(items) {
  const ul = el("ul", { class: "tight" });
  (items || []).forEach((i) => ul.append(el("li", { text: String(i) })));
  if (!(items || []).length) ul.append(el("li", { class: "muted", text: "None." }));
  return ul;
}

function section(title, body) {
  const wrap = el("div");
  wrap.append(el("h2", { text: title }), body);
  return wrap;
}

function renderReport(report) {
  const root = $("report");
  root.replaceChildren();

  // Summary
  if (report.summary) {
    const s = report.summary;
    const kv = el("div", { class: "kv" });
    kv.append(
      el("div", {}, el("span", { class: "k", text: "Main finding" }), el("span", { text: s.main_finding || "—" })),
      el("div", {}, el("span", { class: "k", text: "Recommended action" }), el("span", { text: s.recommended_action || "—" })),
    );
    root.append(section("Summary", kv));
    root.append(section("Top strengths", list(s.top_strengths)));
    root.append(section("Top issues", list(s.top_issues)));
    root.append(section("Required fixes", list(s.required_fixes)));
  }

  // Detection quality scores
  if (report.detection_quality) {
    const q = report.detection_quality;
    const kv = el("div", { class: "kv" });
    const rows = [
      ["Intent alignment", q.intent_alignment_score, 20],
      ["Syntax & schema", q.syntax_schema_score, 15],
      ["Data coverage", q.data_coverage_score, 10],
      ["Precision", q.precision_score, 15],
      ["Recall", q.recall_score, 10],
      ["Performance", q.performance_score, 15],
      ["Sentinel readiness", q.sentinel_readiness_score, 10],
      ["Maintainability", q.maintainability_score, 5],
    ];
    rows.forEach(([label, val, max]) =>
      kv.append(el("div", {}, el("span", { class: "k", text: label }), el("span", { text: `${val ?? "—"} / ${max}` }))),
    );
    kv.append(
      el("div", {}, el("span", { class: "k", text: "False positive risk" }), el("span", { text: q.false_positive_risk || "—" })),
      el("div", {}, el("span", { class: "k", text: "False negative risk" }), el("span", { text: q.false_negative_risk || "—" })),
    );
    root.append(section("Detection quality", kv));
    if ((q.known_blind_spots || []).length) root.append(section("Known blind spots", list(q.known_blind_spots)));
  }

  // Recommended KQL
  if (report.kql && report.kql.recommended_query) {
    root.append(section("Recommended KQL", el("pre", { class: "code" }, el("code", { text: report.kql.recommended_query }))));
    (report.kql.alternative_queries || []).forEach((alt) => {
      root.append(section(`Alternative: ${alt.name || ""}`.trim(),
        el("div", {}, el("p", { class: "muted", text: alt.purpose || "" }), el("pre", { class: "code" }, el("code", { text: alt.query || "" })))));
    });
  }

  // Performance
  if (report.performance) {
    const p = report.performance;
    const kv = el("div", { class: "kv" });
    kv.append(
      el("div", {}, el("span", { class: "k", text: "Rating" }), el("span", { text: p.rating || "—" })),
      el("div", {}, el("span", { class: "k", text: "Execution time (ms)" }), el("span", { text: String(p.execution_time_ms ?? "—") })),
    );
    if (p.statistics_summary) kv.append(el("div", {}, el("span", { class: "k", text: "Statistics" }), el("span", { text: p.statistics_summary })));
    root.append(section("Performance", kv));
    if ((p.bottlenecks || []).length) root.append(section("Bottlenecks", list(p.bottlenecks)));
    if ((p.optimisations || []).length) root.append(section("Optimisations", list(p.optimisations)));
  }

  // Sentinel rule config
  if (report.sentinel_rule) {
    const r = report.sentinel_rule;
    const kv = el("div", { class: "kv" });
    const rows = [
      ["Display name", r.display_name],
      ["Severity", r.severity],
      ["Enabled (recommended)", String(r.enabled_recommendation)],
      ["Query frequency", r.query_frequency],
      ["Query period", r.query_period],
      ["Trigger", `${r.trigger_operator || ""} ${r.trigger_threshold ?? ""}`.trim()],
      ["Tactics", (r.tactics || []).join(", ")],
      ["Techniques", (r.techniques || []).join(", ")],
    ];
    rows.forEach(([k, v]) => kv.append(el("div", {}, el("span", { class: "k", text: k }), el("span", { text: v || "—" }))));
    if (r.description) kv.append(el("div", {}, el("span", { class: "k", text: "Description" }), el("span", { text: r.description })));
    root.append(section("Sentinel rule configuration", kv));
  }

  // Limitations / assumptions
  if ((report.limitations || []).length) root.append(section("Limitations", list(report.limitations)));
  if ((report.assumptions || []).length) root.append(section("Assumptions", list(report.assumptions)));

  $("report-card").classList.remove("hidden");
}

function showVerdict(done) {
  if (done.overall_score == null && !done.verdict) return;
  $("score").textContent = done.overall_score != null ? `${done.overall_score}` : "";
  const vb = $("verdict-badge");
  vb.textContent = done.verdict || "";
  vb.className = "badge " + verdictClass(done.verdict);
  const rb = $("rating-badge");
  rb.textContent = done.rating || "";
  rb.className = "badge";
  $("model-used").textContent = done.modelUsed ? `model: ${done.modelUsed}` : "";
  $("verdict").classList.add("show");
}

function verdictClass(v) {
  if (v === "Deploy as-is") return "ok";
  if (v === "Do not deploy") return "danger";
  if (v === "Deploy after changes" || v === "Test only") return "warn";
  return "";
}

// --- SSE parsing over fetch ----------------------------------------------
function dispatch(event, dataStr) {
  let data = {};
  try { data = JSON.parse(dataStr); } catch { /* keep {} */ }
  switch (event) {
    case "start":
      $("run-title").textContent = `Running (${data.provider}, effort ${data.effort})…`;
      break;
    case "text":
      appendStream(data.text || "");
      break;
    case "thinking":
      addActivity(`thinking: ${truncate(data.text || "", 160)}`, "thinking");
      break;
    case "tool":
      addActivity(`tool: ${data.name}${data.purpose ? " — " + data.purpose : ""}`);
      break;
    case "report":
      lastReport = data;
      renderReport(data);
      break;
    case "done":
      lastMarkdown = data.markdown || "";
      if (data.aborted) addActivity(`aborted: ${data.aborted}`, "err");
      if (data.refusal) addActivity(`refusal noted (${data.refusal.category || "unspecified"}) — model ${data.modelUsed}`, "err");
      showVerdict(data);
      $("run-title").textContent = "Run complete";
      break;
    case "error":
      addActivity(`error: ${data.message || "unknown error"}`, "err");
      $("run-title").textContent = "Run failed";
      break;
  }
}

function truncate(s, n) { return s.length > n ? s.slice(0, n) + "…" : s; }

async function runAnalysis(payload) {
  const res = await fetch("/api/analyse", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok || !res.body) {
    const txt = await res.text().catch(() => "");
    addActivity(`error: server returned ${res.status} ${txt}`, "err");
    return;
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let idx;
    while ((idx = buffer.indexOf("\n\n")) !== -1) {
      const chunk = buffer.slice(0, idx);
      buffer = buffer.slice(idx + 2);
      let event = "message";
      let dataStr = "";
      for (const line of chunk.split("\n")) {
        if (line.startsWith("event:")) event = line.slice(6).trim();
        else if (line.startsWith("data:")) dataStr += line.slice(5).trim();
      }
      if (dataStr) dispatch(event, dataStr);
    }
  }
}

// --- Form submit ---------------------------------------------------------
$("form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const payload = buildPayload();
  if (!payload.request.detection_intent) { alert("Detection intent is required."); return; }
  if (!payload.request.workspace_id) { alert("Workspace ID is required."); return; }
  if (payload.request.mode === "analyse_existing_rule" && !payload.request.kql) {
    alert("KQL is required for analyse mode."); return;
  }

  resetResults();
  const btn = $("run");
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Analysing…';
  try {
    await runAnalysis(payload);
  } catch (err) {
    addActivity(`error: ${err && err.message ? err.message : String(err)}`, "err");
  } finally {
    btn.disabled = false;
    btn.textContent = "Analyse";
  }
});

// --- Downloads -----------------------------------------------------------
function download(name, text, type) {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const a = el("a", { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
$("dl-json").addEventListener("click", () => {
  if (lastReport) download(`${lastReport.analysis_id || "report"}.json`, JSON.stringify(lastReport, null, 2), "application/json");
});
$("dl-md").addEventListener("click", () => {
  if (lastMarkdown) download(`${(lastReport && lastReport.analysis_id) || "report"}.md`, lastMarkdown, "text/markdown");
});
