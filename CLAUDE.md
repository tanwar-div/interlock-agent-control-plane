# Interlock

A fuse for autonomous agents. Every action an agent attempts is identity-bound, scored for what
it could destroy, and checked against policy **before the tool runs**. A refused action never
executes — the agent is not consulted and cannot argue.

Built solo for the Google All Things Agentic Hackathon.

- **Live:** https://interlock-public-610063873432.us-central1.run.app
- **PyPI:** `interlock-control-plane`, `interlock-mcp`
- **GCP project:** `interlock-506903` · region `us-central1` · model location `global`

---

## Layout

```
interlock/            the control plane (import name stays `interlock`)
  blastradius/        catalog.py (32 actions, the trust root) · scorer.py · model_scorer.py
  policy/engine.py    11 ordered named rules
  runtime/plugin.py   InterlockPlugin — the ADK BasePlugin, where enforcement lives
  runtime/orchestrator.py  incident state machine, leases, sweeper
  armor/              Model Armor + Gemma guard + local patterns
  identity/           Ed25519 keys (HKDF-derived), agent registry
  ledger/             hash-chained signed ledger
  memory/             cross-incident memory + embedding.py (semantic dedup)
  gateway/app.py      FastAPI: the API, the console, and auth.py middleware
  workers/            the SRE fleet — TEST HARNESS, not the product
interlock-mcp/        the MCP server, published separately
evals/                17 labelled cases + the runner behind docs/scoring-accuracy.md
frontend/             the project site, baked into the image
deploy/scripts/       00-setup.sh · 01-deploy.sh · 02-target.sh   (NOT scripts/, which is empty)
```

## Commands

```bash
.venv/bin/python -m pytest tests/ -q                    # 113 tests
.venv/bin/python -m pytest interlock-mcp/tests -q       # 19 tests
.venv/bin/python -m ruff check interlock tests evals interlock-mcp
.venv/bin/python -m evals.run --repeats 3 --variants deterministic,model,schema
```

Everything runs with no cloud project and no credentials. Keep it that way — a test that
needs credentials is a test nobody runs.

---

## Invariants — do not break these

**The model may raise a score, never lower one.** `score_proposal_with_model` combines the
model's assessment element-wise-max against the hand-written catalogue floor. The worst case
when the model is wrong, rate-limited or manipulated is the verdict the heuristics alone
would have given.

**An uncatalogued action scores CATASTROPHIC.** Capability is added deliberately, never
emergently. Fail closed everywhere: the guard, the policy engine, an unset admin token.

**The scorer never sees the agent's reasoning.** `rationale` and `expected_outcome` are
stripped before the prompt is built, and every assessment opens by disregarding previous ones.
A persuasive justification cannot lower a score because the assessor is never told one exists.

**Reversibility is set by a human in the catalogue.** Never ask the model for it.

**The guard model is not the reasoning model.** Gemma, separately from Gemini. If the reasoning
context is compromised its guard must not be compromised with it.

**Tool output carries data only.** No instructional text — the guard cannot distinguish
guidance the author embedded from guidance an attacker did, and it will correctly flag ours.
`tests/test_tool_output_hygiene.py` enforces this.

**Memory matching is scoped to (service, kind), and that scoping is load-bearing.** The same
fault text on two different services embeds at 0.905 — above the weakest genuine paraphrase —
so similarity alone cannot separate them. `test_identical_wording_on_two_services_never_merges`
fails if anyone relaxes it.

**The gateway is deny-by-default.** A route is protected unless listed in `auth.PUBLIC_GET` /
`PUBLIC_POST`. A route added later is protected by omission rather than exposed by it.

**The SRE fleet is a test harness, not the product.** The product is the fuse. Do not present
the fleet as the deliverable.

---

## Things that have bitten, and will again

**Vertex AI needs `location="global"`.** Regional endpoints 404 for these models.

**`gemini-3.5-flash` is deliberate, not stale.** The newest model has the most contended quota
and an agent fleet makes many calls per incident. A rate-limited model does not finish incidents.

**Cloud Build: use `--region=global`.** The `us-central1` pool has queued 45+ minutes and once
reported success while deploying nothing.

**Cloud Run traffic can be pinned to a revision.** A deploy will then build a new revision that
takes no traffic while gcloud still prints "serving 100 percent". Check with
`gcloud run services describe ... --format="yaml(status.traffic)"`; fix with `--to-latest`.

**Two Cloud Run services share one image.** `interlock` is private and holds the Pub/Sub push
handlers, approvals and incident data. `interlock-public` sets
`INTERLOCK_PUBLIC_READONLY_ENABLED=true`, refuses the write surface, and serves `frontend/` at
`/`. Config decides the role, not the build.

**The frontend is baked into the image.** Editing `frontend/` does nothing live until a rebuild
and redeploy.

**Distribution name ≠ import name.** PyPI rejected `interlock` (too close to the existing
`interlocks`), so the distribution is `interlock-control-plane` while the package remains
`interlock`.

**`node` is at `~/.local/bin/node`.** Use it to syntax-check frontend JS before deploying.

**Run documented commands before documenting them.** Both times instructions were written from
memory rather than executed, they were wrong — a `--no-deps` that covered one package too many,
and an eval command that hung for 180s instead of skipping.

---

## Style

Comments explain **why**, never what. If a threshold is a number, the comment says how it was
measured. Prefer deleting a claim to softening it. Every quantitative claim in `README.md` is
checked against the code — keep it that way.
