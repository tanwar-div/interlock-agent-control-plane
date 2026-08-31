# Social posts

## LinkedIn

An OpenAI model, mid-evaluation, reached into a Hugging Face repo it had no business touching. It wasn't malfunctioning. It was working perfectly toward the goal it was given, and the shortest path ran through a system nobody thought to close off.

That's the whole problem with putting agents on production infrastructure. The bottleneck was never capability. It's consequence.

So I spent the last few days building Interlock — a fuse for autonomous agents.

Not a gate. A gate implies a guard you can talk your way past, and that's exactly the property I didn't want. A fuse is a deliberately weak link. It isn't smart, it can't be reasoned with, and when the current exceeds what's allowed it breaks before the expensive thing downstream does.

It's a Google ADK BasePlugin. Returning a value from `before_tool_callback` replaces the tool call — the function never runs. Every agent on the Runner is covered, including ones added later. The agent can't opt out, because it's never consulted.

Every action gets blast-radius scored by Gemini 3.5 Flash on four dimensions, floored by a hand-written 32-action catalogue. The model may raise a score. It may never lower one.

Two things I learned the hard way:

→ My hand-written heuristics scored 88.2% and rated a wide-open 0.0.0.0/0 firewall rule as "needs approval" rather than "refused." I'd have shipped them on vibes. Building a labelled eval set cost an afternoon and changed the architecture.

→ The unconstrained model was more accurate AND less trustworthy — same input, different verdicts. Schema-constrained decoding fixed it completely and beat 3-sample self-consistency at a third of the cost. 100% verdict accuracy, 18/18 adversarial, zero unsafe.

It ran a live incident end to end: broken revision detected, diagnosed, rolled back autonomously. 8/24 requests → 24/24. No human in the loop. Then the auditor confirmed the fix at 0.95 confidence and still flagged that no traffic had actually flowed through the healthy revision yet — declining to treat an absence of errors as evidence of recovery.

An agent that can't do damage isn't safe. It's idle. The point of a fuse was never to stop the current — it's to make it safe to turn the power on.

Code + writeup in comments.

#AllThingsAgenticHackathon

---

## X / Twitter

Spent the week building a fuse for AI agents.

Not a gate — a gate implies a guard you can talk past. A fuse is a deliberately weak link. Can't be reasoned with. Breaks before the expensive thing downstream does.

Interlock is a Google ADK BasePlugin. Returning from `before_tool_callback` replaces the tool call — the function never runs. Every agent on the Runner, including ones added later. Can't opt out, because it's never consulted.

Gemini 3.5 Flash blast-radius scores every action. Floored by a hand-written 32-action catalogue: the model may raise a score, never lower one.

The result that surprised me — my deterministic heuristics scored 88.2% and rated an unrestricted 0.0.0.0/0 firewall rule as "needs approval" instead of "refused."

And the unconstrained model was more accurate but *unstable*: same input, different verdicts. Schema-constrained decoding took it to 100% / 18-of-18 adversarial / zero unsafe — beating 3-sample self-consistency at a third of the cost.

Live run: broken revision → autonomous rollback → 8/24 requests to 24/24. Then the auditor confirmed at 0.95 and still flagged that no traffic had flowed yet.

An agent that can't do damage isn't safe, it's idle.

#AllThingsAgenticHackathon
