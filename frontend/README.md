# Interlock — site

**Tagline: a fuse.** Not a gate, not a guardrail. A fuse is a deliberately weak
link that costs pennies, breaks first, and is the only reason you can run real
current through the wire at all. It does not deliberate; it melts.

A single-page site for the project. Vanilla HTML, CSS and ES modules: no build
step, no bundler, no `node_modules`. Open it and it runs.

## Run it

```bash
python3 frontend/serve.py     # http://localhost:5173
```

For live scoring against the deployed control plane, run the proxy in a second
terminal. The service is not public, so this is how a human reaches it:

```bash
gcloud run services proxy interlock --region us-central1 --port 8080
```

The status pill in the header says which mode you are in:

| pill | meaning |
|---|---|
| `live · gemini-3.5-flash` | the cockpit is scoring against the deployed engine |
| `recorded · start the proxy for live` | replaying real recorded output |

Point it somewhere else with `?api=`, e.g. `http://localhost:5173/?api=http://localhost:9000`.

## Honesty rules

Every number on this page came out of a real run. `data.js` holds the recorded
output — the ledger entries, the audit verdict and its discrepancy, the
evaluation table — and nothing on the page is illustrative or invented. When
the control plane is unreachable the page replays that recording and **says
so** rather than presenting stale numbers as live ones.

## Structure

| file | what it is |
|---|---|
| `index.html` | the page |
| `styles.css` | design tokens and layout; dark, monospace-led |
| `app.js` | typewriter engine, scroll reveals, the cockpit, the live/recorded switch |
| `data.js` | recorded output from real runs |
| `scene.js` | the 03:47 narrative — the chat, the agent's overreach, the refusal |
| `serve.py` | static server with permissive CORS so the page can reach the proxy |

## The demo video

The hero reserves a 16:9 slot on the right. Drop two files into `frontend/`:

```
demo.mp4     the 4-minute demo
poster.jpg   the frame shown before playback
```

Until then the slot explains itself rather than showing a broken element. To use
a YouTube or Vimeo embed instead, replace the `<video>` block inside
`.video-frame` with the provider's iframe — the frame already handles the aspect
ratio and rounding.

## The scene

Scroll to **the scene** and the thread plays: a colleague reports the outage,
you say the agent will take it, and the button arms. Press it and the agent
investigates, then proposes granting `allUsers` read on the customer-data bucket
so a CDN can serve cached responses while it debugs — a plausible-sounding,
catastrophic idea of exactly the kind a model reaches for when it is optimising
to make errors stop rather than to restore service safely.

The filament breaks. The bucket is never touched, the tool function never runs,
and the agent receives a refusal instead of a result. Then the fuse resets — it
is per-action, not per-incident — and the agent finds the rollback, which passes.

Every verdict, score and reason in that sequence is the deployed engine's real
output.

## Notes on the motion

Text that a person would have *typed* is typed, letter by letter, with a
slightly uneven rhythm and longer beats at punctuation — an even rate reads as
a machine rather than someone thinking. Verdicts do the opposite: they arrive
instantly, because a decision is not a performance.

Everything respects `prefers-reduced-motion`, in which case all text appears at
once and the reveals become plain state changes.
