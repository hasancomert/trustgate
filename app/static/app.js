"use strict";

// All user-supplied text is rendered with textContent; never innerHTML.
const $ = (selector) => document.querySelector(selector);
const el = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
};

const SEV_RANK = { low: 1, medium: 2, high: 3, critical: 4 };
const VERDICT_TEXT = { safe: "Safe", suspicious: "Suspicious", dangerous: "Dangerous" };
const ACTION_TEXT = {
  proceed: "No strong warning signs. Proceed with normal care.",
  hold: "Hold the payment and verify through a trusted channel first.",
  block: "Do not pay or reply. Treat this as a scam attempt.",
};
const SOURCE_TEXT = { rules: "Rules", links: "Link analysis", sender: "Sender check", payment: "Payment check", llm: "AI analyst" };
const LOADING_STEPS = [
  "Checking manipulation tactics…",
  "Inspecting links without opening them…",
  "Running the text classifier…",
  "Asking the AI analyst…",
  "Combining the signals…",
];
const FLAGS_VISIBLE = 6;
const GAUGE_CIRCUMFERENCE = 2 * Math.PI * 52;

// `run` numbers each submission so a slow response can never overwrite a newer one.
const state = { examples: {}, loadingTimer: null, llmLive: false, run: 0, shareText: "" };
const SHARE_FOOTER = { en: "Check a message yourself:", tr: "Sen de kontrol et:" };

// ------------------------------------------------------------------ setup

document.addEventListener("DOMContentLoaded", () => {
  const form = $("#verify-form");
  form.addEventListener("submit", onSubmit);
  $("#clear").addEventListener("click", () => {
    form.reset();
    updateCounter();
    showOnly("empty");
  });
  $("#message").addEventListener("input", updateCounter);
  document.querySelectorAll("[data-example]").forEach((button) => {
    button.addEventListener("click", () => loadExample(button.dataset.example));
  });
  $("#share-btn").addEventListener("click", shareWarning);
  loadHealth();
  loadExamples();
});

async function loadHealth() {
  const list = $("#layers");
  try {
    const res = await fetch("/api/health");
    const body = await res.json();
    const layers = body.layers || {};
    const model = layers.llm_model ? layers.llm_model.split("/").pop() : null;
    state.llmLive = layers.llm === "live";
    const items = [
      ["Rules", layers.rules === "ok" ? "on" : "off", "on"],
      ["Text classifier", layers.ml === "ok" ? "on" : "off", layers.ml === "ok" ? "on" : "unavailable"],
      ["AI analyst", layers.llm === "live" ? "on" : "mock", layers.llm === "live" ? model || "live" : "mock mode"],
    ];
    list.replaceChildren(...items.map(([name, cls, detail]) => {
      const li = el("li", `layer ${cls}`);
      li.append(el("span", "dot"), el("span", null, `${name}: ${detail}`));
      return li;
    }));
  } catch {
    list.replaceChildren(el("li", "layer off", "API unreachable"));
  }
}

async function loadExamples() {
  try {
    const res = await fetch("/api/examples");
    const items = await res.json();
    items.forEach((item) => { state.examples[item.id] = item; });
  } catch {
    /* buttons stay inert if examples cannot load */
  }
}

function updateCounter() {
  $("#char-count").textContent = $("#message").value.length;
}

// ------------------------------------------------------------------ form <-> payload

function setField(name, value) {
  const field = document.querySelector(`[name="${name}"]`);
  if (!field) return;
  if (field.type === "checkbox") field.checked = Boolean(value);
  else field.value = value === undefined || value === null ? "" : String(value);
}

function loadExample(id) {
  const example = state.examples[id];
  if (!example) return;
  const form = $("#verify-form");
  form.reset();
  const req = example.request;
  setField("message", req.message);
  setField("channel", req.channel || "other");
  setField("ai_agent", req.initiator === "ai_agent");
  const sender = req.sender || {};
  ["display_name", "address", "claimed_organization"].forEach((k) => setField(k, sender[k]));
  const payment = req.payment || {};
  ["amount", "currency", "payee_name", "payee_account", "method", "new_payee"].forEach((k) => setField(k, payment[k]));
  setField("urls", (req.urls || []).join("\n"));
  form.querySelectorAll("details.group").forEach((details) => {
    details.open = [...details.querySelectorAll("input, select, textarea")].some((f) => (f.type === "checkbox" ? f.checked : f.value));
  });
  updateCounter();
  form.requestSubmit();
}

function compact(obj) {
  const out = {};
  Object.entries(obj).forEach(([k, v]) => {
    if (v !== "" && v !== null && v !== undefined && !(typeof v === "number" && Number.isNaN(v))) out[k] = v;
  });
  return Object.keys(out).length ? out : null;
}

function buildPayload(form) {
  const data = new FormData(form);
  const text = (k) => (data.get(k) || "").toString().trim();
  const payload = {
    message: text("message"),
    channel: text("channel") || "other",
    initiator: form.elements.ai_agent.checked ? "ai_agent" : "human",
  };
  const sender = compact({ display_name: text("display_name"), address: text("address"), claimed_organization: text("claimed_organization") });
  if (sender) payload.sender = sender;
  const amount = text("amount");
  const payment = compact({
    amount: amount ? Number(amount) : null,
    currency: text("currency").toUpperCase(),
    payee_name: text("payee_name"),
    payee_account: text("payee_account"),
    method: text("method"),
  });
  const newPayee = form.elements.new_payee.checked;
  if (payment || newPayee) payload.payment = { ...(payment || {}), new_payee: newPayee };
  const urls = text("urls").split(/\s*\n\s*/).filter(Boolean);
  if (urls.length) payload.urls = urls;
  return payload;
}

// ------------------------------------------------------------------ request

async function postVerify(payload, quick) {
  const res = await fetch(quick ? "/api/verify?llm=false" : "/api/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(errorText(res.status, body));
  return body;
}

// With a live LLM, two requests run in parallel: an instant rules + classifier check that is
// shown right away, and the full check whose report replaces it when the AI analyst is done.
async function onSubmit(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const payload = buildPayload(form);
  if (!payload.message) {
    showError("Please paste a message to check.");
    return;
  }
  const run = ++state.run;
  let finalShown = false;
  let preliminaryShown = false;
  startLoading();
  const full = postVerify(payload, false);
  if (state.llmLive) {
    postVerify(payload, true)
      .then((quick) => {
        if (run !== state.run || finalShown) return;
        preliminaryShown = true;
        renderReport(quick, payload.message, true);
      })
      .catch(() => { /* the full request reports any error */ });
  }
  try {
    const report = await full;
    if (run !== state.run) return;
    finalShown = true;
    renderReport(report, payload.message, false);
  } catch (err) {
    if (run !== state.run) return;
    finalShown = true;
    if (preliminaryShown) {
      showPendingNote(`AI analysis unavailable: ${err.message} Showing the rules and classifier result.`);
    } else {
      showError(err.message || "Something went wrong. Please try again.");
    }
  } finally {
    if (run === state.run) stopLoading();
  }
}

function errorText(status, body) {
  if (status === 429) return "Too many checks in a short time. Please wait a minute and try again.";
  if (Array.isArray(body.detail)) return body.detail.map((d) => `${(d.loc || []).slice(1).join(".")}: ${d.msg}`).join("; ");
  return body.detail || `Request failed (${status}).`;
}

function showOnly(id) {
  ["empty", "loading", "error", "report"].forEach((name) => { $(`#${name}`).hidden = name !== id; });
}

function startLoading() {
  showOnly("loading");
  $("#submit").disabled = true;
  let step = 0;
  $("#loading-text").textContent = LOADING_STEPS[0];
  state.loadingTimer = setInterval(() => {
    step = Math.min(step + 1, LOADING_STEPS.length - 1);
    $("#loading-text").textContent = LOADING_STEPS[step];
  }, 1300);
}

function stopLoading() {
  clearInterval(state.loadingTimer);
  $("#submit").disabled = false;
}

function showError(message) {
  $("#error").textContent = message;
  showOnly("error");
}

function showPendingNote(text) {
  const pending = $("#pending");
  pending.textContent = text;
  pending.classList.add("note");
  pending.hidden = false;
}

// ------------------------------------------------------------------ sharing

function renderShare(report) {
  const footer = SHARE_FOOTER[report.language] || SHARE_FOOTER.en;
  state.shareText = report.share_text ? `${report.share_text}\n\n${footer} ${location.origin}` : "";
  $("#share").hidden = !state.shareText;
  $("#share-status").textContent = "";
  $("#share-fallback").hidden = true;
}

// Phones get the native share sheet (WhatsApp, SMS…); desktops copy the text.
async function shareWarning() {
  const text = state.shareText;
  if (!text) return;
  const status = $("#share-status");
  try {
    if (navigator.share && window.matchMedia("(pointer: coarse)").matches) {
      await navigator.share({ text });
      status.textContent = "Shared.";
    } else {
      await navigator.clipboard.writeText(text);
      status.textContent = "Warning copied. Paste it into a chat.";
    }
  } catch (err) {
    if (err && err.name === "AbortError") return; // the share sheet was closed
    const fallback = $("#share-fallback");
    fallback.value = text;
    fallback.hidden = false;
    fallback.select();
    status.textContent = "Copy the warning below.";
  }
}

// ------------------------------------------------------------------ rendering

function renderReport(report, message, preliminary = false) {
  const card = $(".result-card");
  const firstRender = $("#report").hidden;
  card.classList.remove("v-safe", "v-suspicious", "v-dangerous");
  card.classList.add(`v-${report.verdict}`);

  $("#score").textContent = report.risk_score;
  const gauge = $("#gauge-value");
  gauge.setAttribute("stroke-dasharray", GAUGE_CIRCUMFERENCE.toFixed(1));
  gauge.setAttribute("stroke-dashoffset", (GAUGE_CIRCUMFERENCE * (1 - report.risk_score / 100)).toFixed(1));
  $("#verdict").textContent = VERDICT_TEXT[report.verdict] || report.verdict;
  $("#scam-type").textContent = report.scam_type === "none" ? "No scam pattern detected" : report.scam_type_label;
  $("#action").textContent = ACTION_TEXT[report.recommended_action] || "";
  $("#summary").textContent = report.summary;

  renderHighlighted($("#highlighted"), message, report.red_flags);
  renderFlags(report.red_flags);
  renderLinks(report.link_findings);
  $("#steps").replaceChildren(...report.safe_steps.map((step) => el("li", null, step)));
  renderShare(report);
  renderSignals(report.signals, preliminary);
  $("#disclaimer").textContent = report.disclaimer;
  const llm = report.signals.llm;
  $("#meta").textContent = preliminary
    ? `Preliminary result from rules + text classifier in ${report.latency_ms} ms · engine v${report.engine_version}`
    : `Checked in ${report.latency_ms} ms · engine v${report.engine_version} · AI analyst: ${llm.status}`;
  const pending = $("#pending");
  pending.textContent = "AI analyst is reviewing…";
  pending.classList.remove("note");
  pending.hidden = !preliminary;

  showOnly("report");
  if (firstRender && window.matchMedia("(max-width: 960px)").matches) card.scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderHighlighted(container, text, flags) {
  // Offsets from the API count Unicode code points (Python); JS strings count UTF-16 units,
  // so slice an array of code points to keep emoji and other astral characters intact.
  const chars = Array.from(text);
  const spans = flags.filter((f) => Number.isInteger(f.start) && Number.isInteger(f.end) && f.end > f.start && f.end <= chars.length);
  const points = [...new Set([0, chars.length, ...spans.flatMap((f) => [f.start, f.end])])].sort((a, b) => a - b);
  const nodes = [];
  let last = null;
  for (let i = 0; i < points.length - 1; i += 1) {
    const [a, b] = [points[i], points[i + 1]];
    const chunk = chars.slice(a, b).join("");
    const covering = spans.filter((f) => f.start <= a && f.end >= b);
    if (!covering.length) {
      nodes.push(document.createTextNode(chunk));
      last = null;
      continue;
    }
    const top = covering.reduce((m, f) => (SEV_RANK[f.severity] > SEV_RANK[m.severity] ? f : m));
    const tip = [...new Set(covering.map((f) => f.title))].join("\n");
    if (last && last.dataset.tip === tip && last.classList.contains(`sev-${top.severity}`)) {
      last.textContent += chunk;
    } else {
      last = el("mark", `sev-${top.severity}`, chunk);
      last.dataset.tip = tip;
      last.tabIndex = 0;
      nodes.push(last);
    }
    last.setAttribute("aria-label", `${last.textContent}: ${tip.replace(/\n/g, ", ")}`);
  }
  container.replaceChildren(...nodes);
}

function flagItem(flag) {
  const li = el("li", "flag");
  li.append(el("span", `sev sev-${flag.severity}`, flag.severity));
  const title = el("div", "flag-title", flag.title);
  title.append(el("span", "flag-source", SOURCE_TEXT[flag.source] || flag.source));
  li.append(title);
  li.append(el("div", "flag-why", flag.explanation));
  flag.evidence.forEach((phrase) => li.append(el("code", "flag-evidence", phrase)));
  return li;
}

// A rule that fires on several phrases gets one card that quotes each of them, under its strongest severity.
function groupFlags(flags) {
  const groups = new Map();
  for (const flag of flags) {
    const key = [flag.source, flag.rule_id, flag.title].join("\n");
    const group = groups.get(key);
    if (!group) {
      groups.set(key, { ...flag, evidence: flag.evidence ? [flag.evidence] : [] });
      continue;
    }
    if (SEV_RANK[flag.severity] > SEV_RANK[group.severity]) group.severity = flag.severity;
    if (flag.evidence && !group.evidence.includes(flag.evidence)) group.evidence.push(flag.evidence);
  }
  return [...groups.values()];
}

function renderFlags(flags) {
  const list = $("#flags");
  const sorted = groupFlags(flags).sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity]);
  $("#flag-count").textContent = `(${sorted.length})`;
  if (!sorted.length) {
    list.replaceChildren(el("li", "muted", "No red flags found."));
    return;
  }
  const items = sorted.map(flagItem);
  items.slice(FLAGS_VISIBLE).forEach((item) => { item.hidden = true; });
  list.replaceChildren(...items);
  if (items.length > FLAGS_VISIBLE) {
    const more = el("button", "more", `Show ${items.length - FLAGS_VISIBLE} more`);
    more.type = "button";
    more.addEventListener("click", () => {
      items.forEach((item) => { item.hidden = false; });
      more.remove();
    });
    const li = el("li");
    li.append(more);
    list.append(li);
  }
}

function renderLinks(findings) {
  $("#links-section").hidden = !findings.length;
  $("#links").replaceChildren(...findings.map((finding) => {
    const li = el("li", "link");
    li.append(el("div", "link-url", finding.url));
    const domain = el("div", "link-domain", "Real destination: ");
    domain.append(el("strong", null, finding.registered_domain));
    if (finding.impersonated_brand) {
      domain.append(document.createTextNode(" · "));
      domain.append(el("span", "brand-warning", `imitates ${finding.impersonated_brand}`));
    }
    li.append(domain);
    if (finding.issues.length) {
      const ul = el("ul", "link-issues");
      finding.issues.forEach((issue) => ul.append(el("li", null, issue)));
      li.append(ul);
    } else {
      li.append(el("div", "link-domain", "No structural issues found."));
    }
    return li;
  }));
}

function renderSignals(signals, preliminary = false) {
  const rows = [
    ["Rules", "Tactics & links", signals.rules],
    ["Text classifier", "TF-IDF + LR", signals.ml],
    ["AI analyst", "LLM", signals.llm],
  ];
  const container = $("#signals");
  const nodes = rows.map(([name, sub, layer]) => {
    const row = el("div", "signal-row");
    const label = el("div", "signal-name", name);
    const status = preliminary && layer.status === "skipped" ? "reviewing…" : layer.status;
    label.append(el("small", null, layer.score === null ? status : `${sub} · weight ${Math.round(layer.effective_weight * 100)}%`));
    const bar = el("div", "bar");
    const fill = el("span");
    fill.style.width = `${layer.score === null ? 0 : layer.score}%`;
    bar.append(fill);
    row.append(label, bar, el("div", "signal-score", layer.score === null ? "n/a" : Math.round(layer.score)));
    if (layer.detail) row.append(el("div", "signal-detail", layer.detail));
    return row;
  });
  const note = el("p", "signal-note", `Weighted score ${Math.round(signals.weighted_score)}.`);
  if (signals.floor_applied) note.textContent += ` A high-risk pattern raised the final score to at least ${signals.floor_applied}.`;
  container.replaceChildren(...nodes, note);
}
