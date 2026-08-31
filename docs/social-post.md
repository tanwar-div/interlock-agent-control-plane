# Social posts

## LinkedIn

Interlock — a fuse for autonomous agents. Every action an agent attempts is checked before the tool runs.

It installs as a Google ADK `BasePlugin`. In ADK, returning a value from `before_tool_callback` *replaces* the tool call, so the function never executes. Not rolled back — never runs. It covers every agent on the Runner, including sub-agents and ones added later, and the agent can't opt out because it's never consulted.

Each intercepted call clears six stages:

→ **Identity** — Ed25519-signed proposal checked against a registry-signed agent card
→ **Capability** — per-agent tool allowlist and severity ceiling
→ **Blast radius** — Gemini 3.5 Flash scores data, availability, privilege and scope, from the arguments alone
→ **Content** — Model Armor + a separate Gemma classifier inspect anything the agent didn't write
→ **Policy** — 11 ordered rules resolve to ALLOW / REQUIRE_APPROVAL / DENY
→ **Evidence** — every decision appended to a hash-chained, signed ledger

Two design choices do most of the work.

The scorer never sees the proposing agent's reasoning — only the action type, its target and its literal arguments. A persuasive justification can't lower a score, because the assessor is never told one exists.

And a hand-written catalogue of 32 actions sets a floor on every dimension. The model may raise a score and may never lower one, so the worst case if it's wrong, rate-limited or manipulated is the verdict the hand-written rules would have given alone.

Live, no account needed:
🔗 interlock-public-610063873432.us-central1.run.app

#AllThingsAgenticHackathon

---

## X / Twitter

Built Interlock — a fuse for autonomous agents.

It's a Google ADK BasePlugin. Returning from `before_tool_callback` replaces the tool call, so a refused action never executes.

Six stages before anything runs: identity, capability, blast radius, content, policy, signed ledger.

Gemini 3.5 Flash scores what an action could destroy — from the arguments alone, never the agent's reasoning. A hand-written 32-action catalogue floors it: the model can raise a score, never lower one.

Live, no account:
interlock-public-610063873432.us-central1.run.app

#AllThingsAgenticHackathon
