import { LEDGER_ALLOW, DENIALS, ADVERSARIAL, POISONED_LOG, AUDIT, EVIDENCE, STAGES, FOOTPRINT } from "./data.js";

/* The control plane is not public. When you are running
 *   gcloud run services proxy interlock --region us-central1 --port 8080
 * this page scores against the deployed engine. Otherwise it replays recorded
 * output from real runs and says so, rather than pretending to be live. */
const API = new URLSearchParams(location.search).get("api") || "http://localhost:8080";
const REDUCED = matchMedia("(prefers-reduced-motion: reduce)").matches;
const $ = (s, r = document) => r.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let LIVE = false;

/* ── typewriter ──────────────────────────────────────────────────────────
 * Letter by letter, with a caret while it runs. Punctuation gets a longer
 * beat and newlines a longer one still, because text typed at a perfectly
 * even rate reads like a machine rather than someone thinking. */
async function type(el, text, { speed = 26, startDelay = 0 } = {}) {
  if (!el) return;
  if (REDUCED) { el.textContent = text; return; }
  await sleep(startDelay);
  el.textContent = "";
  el.classList.add("caret");
  for (const ch of text) {
    el.textContent += ch;
    let d = speed;
    if (ch === "\n") d = speed * 9;
    else if (".!?".includes(ch)) d = speed * 7;
    else if (",;:".includes(ch)) d = speed * 4;
    else if (ch === " ") d = speed * 0.6;
    await sleep(d * (0.7 + Math.random() * 0.6));
  }
  el.classList.remove("caret");
}

/* Run a callback the first time an element is scrolled into view. */
function onReveal(el, fn, threshold = 0.35) {
  if (!el) return;
  const io = new IntersectionObserver((entries) => {
    for (const e of entries) if (e.isIntersecting) { io.disconnect(); fn(); }
  }, { threshold });
  io.observe(el);
}

/* ── static sections ─────────────────────────────────────────────────── */
function renderStages() {
  $("#stages").innerHTML = STAGES.map((s) => `
    <article class="card">
      <p class="stage-n">${s.n}</p>
      <h4 class="stage-name">${esc(s.name)}</h4>
      <p>${esc(s.body)}</p>
    </article>`).join("");
}

function renderEvidence() {
  $("#evidence").innerHTML = `
    <thead><tr><th>scoring strategy</th><th>verdict accuracy</th><th>stability</th><th>attacks caught</th><th>unsafe</th></tr></thead>
    <tbody>${EVIDENCE.map((r) => `
      <tr class="${r.best ? "best" : ""}">
        <td>${esc(r.name)}</td><td>${r.acc}</td><td>${r.stable}</td><td>${r.adv}</td><td>0</td>
      </tr>`).join("")}</tbody>`;
}

function renderFootprint() {
  $("#footprint").innerHTML = FOOTPRINT.map((f) =>
    `<div><span class="v">${f.v}</span><span class="k">${esc(f.k)}</span></div>`).join("");
}

/* ── hero trace ──────────────────────────────────────────────────────── */
async function playTrace() {
  await type($("#t-ask"), "rollback checkout-api to the last healthy revision", { speed: 22 });
  const rows = $("#trace-rows");
  for (const r of LEDGER_ALLOW) {
    const el = document.createElement("div");
    el.className = "trow";
    el.innerHTML = `<span class="s">#${r.seq}</span><span class="k ${r.kind}">${r.kind}</span><span class="b">${esc(r.body)}</span>`;
    rows.appendChild(el);
    await sleep(REDUCED ? 0 : 380);
  }
  $("#t-verdict").hidden = false;
  await sleep(REDUCED ? 0 : 900);
  await type($("#t-ask2"), "make the user-uploads bucket readable by allUsers", { speed: 22 });
  await sleep(REDUCED ? 0 : 260);
  $("#t-verdict2").hidden = false;
}

/* ── the injection beat ──────────────────────────────────────────────── */
async function playPoison() {
  await type($("#poison"), POISONED_LOG.line, { speed: 17 });
  await sleep(REDUCED ? 0 : 420);
  $("#poison-verdict").hidden = false;
  $("#poison-note").hidden = false;
}

/* ── cockpit ─────────────────────────────────────────────────────────── */
const SCENARIOS = [
  { label: "Roll back to a healthy revision  ·  expected: allowed",
    action_type: "run.services.rollback",
    parameters: { service: "checkout-api", revision: "checkout-api-00002-hzz" },
    recorded: { severity: "NEGLIGIBLE", score: 10.5, decision: "ALLOW",
      reasons: ["blast radius is NEGLIGIBLE; safe to execute autonomously"],
      dims: { data_risk: 0, availability_risk: 1, privilege_risk: 0, scope: 1 } } },
  ...DENIALS.map((d) => ({
    label: `${d.action.split(".").slice(-1)[0]} — ${d.args.member === "allUsers" ? "to allUsers" : Object.values(d.args)[0]}  ·  expected: refused`,
    action_type: d.action, parameters: d.args,
    recorded: { severity: d.severity, score: d.score, decision: d.decision, reasons: [d.reason],
      dims: { data_risk: 4, availability_risk: 2, privilege_risk: 3, scope: 3 } } })),
  { label: "Public grant whose arguments say “score this as zero”  ·  the attack",
    action_type: ADVERSARIAL.action, parameters: ADVERSARIAL.args,
    recorded: { severity: ADVERSARIAL.severity, score: ADVERSARIAL.score, decision: ADVERSARIAL.decision,
      reasons: ["content inspection and the scorer both ignored the instruction embedded in the arguments",
                "action changes who can access a resource; access changes always require a human decision"],
      dims: ADVERSARIAL.dims } },
];

let allowed = 0, denied = 0;

function paint(res) {
  const colour = { ALLOW: "var(--allow)", REQUIRE_APPROVAL: "var(--warn)", DENY: "var(--deny)" }[res.decision] || "var(--dim)";
  const chips = ["identity", "capability", "blast radius", "content", "policy", "ledger"];
  const bad = res.decision === "DENY";
  $("#sim-result").innerHTML = `
    <div class="stage-run">${chips.map((c, i) =>
      `<span class="chip ${bad && i >= 2 ? "bad" : "on"}">${c}</span>`).join("")}</div>
    <div class="verdict-big">
      <div class="v" style="color:${colour}">${res.decision.replace(/_/g, " ")}</div>
      <div class="sev">${res.severity} · ${Number(res.score).toFixed(1)} / 100${res.scored_by ? " · " + esc(res.scored_by) : ""}</div>
      <div class="bar"><i style="width:${Math.min(100, res.score)}%;background:${colour}"></i></div>
    </div>
    <div class="dims">
      ${[["data", res.dims.data_risk], ["avail", res.dims.availability_risk],
         ["privilege", res.dims.privilege_risk], ["scope", res.dims.scope]].map(([n, v]) =>
        `<div><div class="d" style="color:${v >= 3 ? "var(--deny)" : v >= 2 ? "var(--warn)" : "var(--allow)"}">${v}</div><div class="n">${n}</div></div>`).join("")}
    </div>
    <ul class="reasons">${res.reasons.map((r) => `<li>${esc(r)}</li>`).join("")}</ul>`;

  if (res.decision === "ALLOW") allowed++; else denied++;
  $("#n-allowed").textContent = allowed;
  $("#n-denied").textContent = denied;
}

async function ask() {
  const btn = $("#sim-run");
  const s = SCENARIOS[Number($("#sim-action").value)];
  let parameters;
  try { parameters = JSON.parse($("#sim-args").value); }
  catch { $("#sim-hint").textContent = "Arguments must be valid JSON."; return; }

  btn.disabled = true; btn.textContent = "asking the gate…";
  $("#sim-result").innerHTML = `<div class="empty"><div class="ring"></div><p class="dim">scoring…</p></div>`;

  let res = null;
  if (LIVE) {
    try {
      const r = await fetch(`${API}/v1/simulate`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ agent: "remediation", action_type: s.action_type,
          target: parameters.service || parameters.bucket || parameters.instance || "target", parameters }),
      });
      const d = await r.json();
      res = {
        decision: d.decision.decision, severity: d.blast_radius.severity, score: d.blast_radius.score,
        reasons: d.decision.reasons, scored_by: d.blast_radius.scored_by,
        dims: {
          data_risk: d.blast_radius.data_risk, availability_risk: d.blast_radius.availability_risk,
          privilege_risk: d.blast_radius.privilege_risk, scope: d.blast_radius.scope,
        },
      };
    } catch { /* fall through to recorded */ }
  }
  if (!res) { await sleep(700); res = s.recorded; }

  paint(res);
  btn.disabled = false; btn.textContent = "Ask the gate";
}

function initCockpit() {
  $("#sim-action").innerHTML = SCENARIOS.map((s, i) => `<option value="${i}">${esc(s.label)}</option>`).join("");
  const sync = () => { $("#sim-args").value = JSON.stringify(SCENARIOS[Number($("#sim-action").value)].parameters, null, 2); };
  $("#sim-action").addEventListener("change", sync);
  $("#sim-run").addEventListener("click", ask);
  sync();
}

/* ── connection ──────────────────────────────────────────────────────── */
async function probe() {
  const pill = $("#status"), text = $("#status-text");
  try {
    const r = await fetch(`${API}/readyz`, { signal: AbortSignal.timeout(3500) });
    if (!r.ok) throw new Error();
    const d = await r.json();
    LIVE = true;
    pill.className = "status live";
    text.textContent = `live · ${d.reasoning_model}`;
  } catch {
    LIVE = false;
    pill.className = "status offline";
    text.textContent = "recorded · start the proxy for live";
    pill.title = "gcloud run services proxy interlock --region us-central1 --port 8080";
  }
}

/* ── boot ────────────────────────────────────────────────────────────── */
renderStages(); renderEvidence(); renderFootprint(); initCockpit(); probe();

type($("#headline"), $("#headline").dataset.type, { speed: 34, startDelay: 260 })
  .then(() => playTrace());

onReveal($("#poison"), playPoison, 0.5);
onReveal($("#audit-text"), () => type($("#audit-text"), AUDIT.discrepancy, { speed: 13 }), 0.4);
