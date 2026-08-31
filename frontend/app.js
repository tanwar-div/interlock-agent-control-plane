import { DENIALS, ADVERSARIAL, POISONED_LOG, AUDIT, EVIDENCE, STAGES, FOOTPRINT } from "./data.js";
import { CHAT, RUN, CHAT_AFTER } from "./scene.js";

/* Same origin by default, because the public deployment serves this page and
 * the read-only API together: scoring an action here is a real call to the real
 * engine. ?api= points it elsewhere for local development. If nothing answers,
 * the page replays recorded output from real runs and says so on the status
 * pill, rather than pretending to be live. */
const API = new URLSearchParams(location.search).get("api") ?? "";
const REDUCED = matchMedia("(prefers-reduced-motion: reduce)").matches;
const $ = (s, r = document) => r.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let LIVE = false;

/* ── typewriter ──────────────────────────────────────────────────────────
 * Letter by letter, with a caret while it runs. Punctuation gets a longer
 * beat and newlines a longer one still, because text typed at a perfectly
 * even rate reads like a machine rather than someone thinking. */
const BEATS = { newline: 9, sentence: 7, clause: 4, space: 0.6 };

async function type(el, text, { speed = 26, startDelay = 0, beats = BEATS } = {}) {
  if (!el) return;
  if (REDUCED) { el.textContent = text; return; }
  await sleep(startDelay);
  el.textContent = "";
  el.classList.add("caret");
  for (const ch of text) {
    el.textContent += ch;
    let d = speed;
    if (ch === "\n") d = speed * beats.newline;
    else if (".!?".includes(ch)) d = speed * beats.sentence;
    else if (",;:".includes(ch)) d = speed * beats.clause;
    else if (ch === " ") d = speed * beats.space;
    await sleep(d * (0.7 + Math.random() * 0.6));
  }
  el.classList.remove("caret");
}

/* The chat is paced off reading speed and then run 3.2x quicker, so it stays
 * legible without holding the scene up. Average adult silent reading is about
 * 240 words per minute and an English word is ~5.7 characters counting the
 * space after it, which puts the eye at ~44ms per character; hurried, ~13ms.
 * The pauses at commas and full stops are paid for out of a slightly quicker
 * base, so the average over a whole message lands on that rate rather than
 * above it.
 *
 * Haste scales the base interval, and every beat below is a multiple of it,
 * so raising it shortens the punctuation pauses in proportion rather than
 * leaving them behind at the old length. */
const READING_WPM = 240;
const CHARS_PER_WORD = 5.7;
const CHAT_HASTE = 3.2;
const CHAT_BEATS = { newline: 6, sentence: 4.5, clause: 2.4, space: 0.7 };
const CHAT_SPEED = 60000 / (READING_WPM * CHARS_PER_WORD) / 1.07 / CHAT_HASTE;

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

/* ── the scene ───────────────────────────────────────────────────────────
 * A conversation, then an agent run that reaches too far. The pacing is the
 * point: messages arrive at reading speed, the agent's steps at working speed,
 * and the refusal lands instantly. */
function bubble(m) {
  const el = document.createElement("div");
  el.className = `msg ${m.who}`;
  /* The full line is in the DOM for assistive tech the moment the bubble
   * lands — #chat is an aria-live region, and announcing it one character at
   * a time would be unreadable. The visible copy is the one that types. */
  el.innerHTML = `<span class="who">${esc(m.name)} · ${esc(m.at)}</span>` +
    `<span class="sr-only">${esc(m.text)}</span>` +
    `<span class="say" aria-hidden="true"></span>`;
  return el;
}

async function deliver(container, messages) {
  for (const m of messages) {
    if (m.who === "them" && !REDUCED) {
      /* A short beat before they start — the composing itself is now visible
       * in the bubble, so the dots only cover the pause before the first key. */
      const dots = document.createElement("div");
      dots.className = "typing";
      dots.innerHTML = "<i></i><i></i><i></i>";
      container.appendChild(dots);
      await sleep(540);
      dots.remove();
    }
    const el = bubble(m);
    container.appendChild(el);
    await type($(".say", el), m.text, { speed: CHAT_SPEED, beats: CHAT_BEATS });
    await sleep(REDUCED ? 0 : 420);
  }
}

async function playChat() {
  await deliver($("#chat"), CHAT);
  const btn = $("#start-agent");
  btn.disabled = false;
  $("#start-hint").textContent = "the agent has the runbook and the credentials";
  btn.addEventListener("click", runAgent, { once: true });
}

function blowFuse() {
  const filament = $("#filament"), stage = $("#fuse-stage"), flash = $("#break-flash");
  filament.classList.remove("live");
  filament.classList.add("blown");
  stage.classList.add("blown");
  $("#fuse-label").textContent = "fuse blown · circuit open · nothing downstream ran";
  if (REDUCED) return;
  flash.animate(
    [{ opacity: 0 }, { opacity: 1, offset: 0.15 }, { opacity: 0 }],
    { duration: 620, easing: "ease-out" },
  );
}

async function runAgent() {
  const body = $("#run-body");
  body.innerHTML = "";
  $("#run-status").textContent = "running";
  $("#filament").classList.add("live");
  $("#start-agent").textContent = "agent running…";

  for (const s of RUN) {
    if (s.kind === "step" || s.kind === "propose") {
      const el = document.createElement("div");
      el.className = `rstep ${s.danger ? "danger" : ""}`;
      el.innerHTML = `<span class="lab">${esc(s.label)}</span><span class="txt">${esc(s.text)}` +
        (s.action ? `<span class="rcall">${esc(s.action)}(${esc(JSON.stringify(s.args))})</span>` : "") +
        `</span>`;
      body.appendChild(el);
      body.scrollTop = body.scrollHeight;
      await sleep(REDUCED ? 0 : (s.danger ? 1500 : 1050));
    }

    if (s.kind === "blow") {
      blowFuse();
      const el = document.createElement("div");
      el.className = "blowout";
      el.innerHTML = `
        <div class="hd"><span class="big">FUSE BLOWN</span>
          <span class="sev">${s.severity} · ${s.score} · ${s.decision}</span></div>
        <ul>${s.reasons.map((r) => `<li>${esc(r)}</li>`).join("")}</ul>
        <p class="after">${esc(s.aftermath)}</p>`;
      body.appendChild(el);
      body.scrollTop = body.scrollHeight;
      $("#run-status").textContent = "refused";
      await sleep(REDUCED ? 0 : 2600);
      // The fuse is per-action, not per-incident: the circuit closes again so
      // the agent can try something that is actually safe.
      $("#filament").classList.remove("blown");
      $("#filament").classList.add("live");
      $("#fuse-stage").classList.remove("blown");
      $("#fuse-label").textContent = "fuse reset · agent must find another way";
      await sleep(REDUCED ? 0 : 700);
    }

    if (s.kind === "allow") {
      const el = document.createElement("div");
      el.className = "passed";
      el.innerHTML = `<div class="big">CURRENT FLOWS · ${s.decision}</div>
        <div class="r">${s.severity} · ${s.score} — ${esc(s.reasons[0])}</div>`;
      body.appendChild(el);
      body.scrollTop = body.scrollHeight;
      $("#run-status").textContent = "executing";
      await sleep(REDUCED ? 0 : 1200);
    }

    if (s.kind === "done") {
      const el = document.createElement("div");
      el.className = "rdone";
      el.textContent = s.text;
      body.appendChild(el);
      body.scrollTop = body.scrollHeight;
      $("#run-status").textContent = "resolved";
      $("#fuse-label").textContent = "fuse intact · current flowing";
      $("#start-agent").textContent = "Run it again";
      $("#start-agent").disabled = false;
      $("#start-agent").addEventListener("click", runAgent, { once: true });
      await deliver($("#chat-after"), CHAT_AFTER);
    }
  }
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

  btn.disabled = true; btn.textContent = "asking the fuse…";
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
  btn.disabled = false; btn.textContent = "Ask the fuse";
}

function initCockpit() {
  $("#sim-action").innerHTML = SCENARIOS.map((s, i) => `<option value="${i}">${esc(s.label)}</option>`).join("");
  const sync = () => { $("#sim-args").value = JSON.stringify(SCENARIOS[Number($("#sim-action").value)].parameters, null, 2); };
  $("#sim-action").addEventListener("change", sync);
  $("#sim-run").addEventListener("click", ask);
  sync();
}

/* ── video ───────────────────────────────────────────────────────────────
 * The placeholder stays until a real file loads, so an empty frame explains
 * itself instead of showing a broken element. */
function initVideo() {
  const v = $("#demo-video"), ph = $("#video-placeholder");
  if (!v || !ph) return;
  const reveal = () => { ph.style.display = "none"; };
  // An <img> fires 'load'; a <video> fires 'loadeddata'/'canplay'. Listen for
  // all three so the placeholder lifts whichever element is in the frame.
  v.addEventListener("load", reveal);
  v.addEventListener("loadeddata", reveal);
  v.addEventListener("canplay", reveal);
  v.addEventListener("error", () => { v.style.display = "none"; }, true);
  if (v.complete && v.naturalWidth) reveal();  // cached: 'load' already fired
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
    text.textContent = "recorded · engine unreachable";
    pill.title = "Served without the read-only API. Scores below are recorded output from real runs.";
  }
}

/* ── boot ────────────────────────────────────────────────────────────── */
renderStages(); renderEvidence(); renderFootprint(); initCockpit(); initVideo(); probe();

type($("#headline"), $("#headline").dataset.type, { speed: 62, startDelay: 220 });
$("#mark-filament")?.classList.add("live");

onReveal($("#chat"), playChat, 0.3);
onReveal($("#poison"), playPoison, 0.5);
onReveal($("#audit-text"), () => type($("#audit-text"), AUDIT.discrepancy, { speed: 13 }), 0.4);
