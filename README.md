# Arachnode Agent Security Gateway

A control layer that sits between an AI agent and the real actions it's
trying to take. Every request the agent sends goes through `/decide`
first, and comes back with one of five decisions:

| Decision | Meaning | What happens next |
|---|---|---|
| `ALLOW` | No risk pattern matched | Action proceeds normally |
| `BLOCK` | Matches a known high-risk pattern | Action refused outright |
| `REQUIRE_APPROVAL` | Needs a human judgment call | Paused for Master Discernment Key approval |
| `CAPTURE` | Suspicious, not yet proven | Routed into one of 8 digital-twin mirrors (the Mirror Maze) |
| `QUARANTINE` | Confirmed suspicious inside the maze | Sealed off permanently (the Trapdoor) — every future request auto-refused |

## Digital Twin x8 — the Mirror Maze

When a request looks suspicious but isn't proven malicious, the agent
isn't blocked — it's dropped into one of 8 synthetic "digital twin"
copies of the real system (styled after a spider's eight eyes). The
same agent always lands on the same mirror for the length of its
session, and every twin is deliberately different from the others, so
nothing the agent sees can be trusted as ground truth, and two
suspicious sessions comparing notes won't match. Nothing it touches in
there is real; every move is logged.

## The Trapdoor — Quarantine

An agent can't wander the maze forever. After `TRAPDOOR_MOVE_LIMIT`
(default: 3) moves inside a mirror, the trapdoor opens: the agent falls
into Quarantine, a sealed one-way state. Once quarantined, that agent
ID can never get back to `ALLOW`, `BLOCK`, or `REQUIRE_APPROVAL` — every
future request is auto-refused without re-evaluation, like a
cryptographic trapdoor function: easy to fall through, effectively
impossible to reverse.

## Running it locally

1. Open a terminal in this folder.
2. Create a virtual environment: `python -m venv .venv`
3. Activate it:
   - Windows: `.venv\Scripts\activate`
   - Mac/Linux: `source .venv/bin/activate`
4. Install dependencies: `pip install -r requirements.txt`
5. Start the server: `uvicorn main:app --reload`
6. Open `http://127.0.0.1:8000/docs` in a browser — that's an
   interactive page where you can try every endpoint by clicking
   "Try it out."

## Running the tests

```
pip install -r requirements-dev.txt
pytest
```

## Endpoints

- `POST /decide` — the main endpoint. Send `{"agent_id", "action", "resource", "data"}`.
- `POST /approve/{approval_id}` / `POST /deny/{approval_id}` — resolve a paused `REQUIRE_APPROVAL`.
- `GET /pending-approvals` — requests currently waiting on a human.
- `GET /mirror-maze/status` — who's currently inside the maze, and which mirror.
- `GET /quarantine/status` — who has fallen through the trapdoor.
- `GET /audit-log` — every decision ever made, as a permanent record.
- `GET /health` — for uptime checks.

## Optional API key

By default there's no auth (fine for local dev and a live demo you
control the link to). To lock it down, set an environment variable
`GATEWAY_API_KEY` to any secret value — every request then needs a
header `X-API-Key: <that same value>`, or it's refused with 401.

## Deploying to Render

This repo includes a `render.yaml` (Render calls this a "Blueprint"),
so Render can build and run it with almost no manual setup:

1. Push this repo to GitHub.
2. In the Render dashboard, click **New +** then **Blueprint**.
3. Pick this repo. Render reads `render.yaml` and creates the service
   automatically (it builds the `Dockerfile`).
4. If you want the API key enforced in production, add an environment
   variable `GATEWAY_API_KEY` with a secret value on the service's
   **Environment** tab in Render.
5. Once it deploys, your gateway is live at the `.onrender.com` URL
   Render gives you. Check `/health` first, then `/docs`.

## What's simplified for this demo version

- **In-memory storage.** Mirror-maze sessions, quarantine list, and
  pending approvals live in memory and reset if the process restarts.
  Good enough to demo; a production version would persist these (e.g.
  to a database) the way the main Arachnode MVP does with its audit
  chain.
- **Keyword-based classifier.** `classify_request()` matches on simple
  keyword lists — it's the seed of the real policy engine, not the
  final version.
