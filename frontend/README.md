# Interlock — site

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
| `serve.py` | static server with permissive CORS so the page can reach the proxy |

## Notes on the motion

Text that a person would have *typed* is typed, letter by letter, with a
slightly uneven rhythm and longer beats at punctuation — an even rate reads as
a machine rather than someone thinking. Verdicts do the opposite: they arrive
instantly, because a decision is not a performance.

Everything respects `prefers-reduced-motion`, in which case all text appears at
once and the reveals become plain state changes.
