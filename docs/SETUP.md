# VulnIQ — Setup Guide (from zero to running)

This walks you through everything **on your side**, in order. Two parts:
**A)** get & set your Anthropic API key, **B)** run the backend + dashboard.

Everything works **without** a key too (deterministic fallbacks), but the key is
what turns on the real AI: deep file extraction, semantic chaining, LLM chain
narratives, and the live copilot.

---

## Part A — Get your Anthropic API key

You said you haven't bought it yet. Here's exactly how:

1. Go to **https://console.anthropic.com** and sign up / log in.
2. In the left sidebar, open **Billing** → add a payment method and buy some
   credits. For this project, **$5–$10 is plenty** — extraction + chaining on a
   few hundred findings costs cents, not dollars. (You can set a monthly spend
   cap on the same page so there are no surprises.)
3. In the left sidebar, open **API keys** → **Create Key**. Give it a name like
   `vulniq-warp`. Copy the key — it starts with `sk-ant-...`.
   **You only see it once**, so paste it somewhere safe immediately.

That's it. You now have a key. Do **not** put it in any file you commit to
GitHub — we'll set it as an environment variable instead (next section).

> Rough cost intuition: Claude Opus pricing is per-token. A full ingest of ~300
> findings across files, plus building all chains and narratives, is well under
> a dollar. The dashboard copilot is a few cents per conversation. Keep a $10
> cap and you cannot overspend.

---

## Part B — Run the backend + dashboard

### Prerequisites
- **Python 3.10+** (`python3 --version` to check)
- **Node.js** is NOT required — the dashboard is a single HTML file.

### Step 1 — Get the code onto your machine
Unzip the `vulniq` folder somewhere, then open a terminal in it:
```bash
cd path/to/vulniq/backend
```

### Step 2 — Create a virtual environment (keeps deps isolated)
```bash
python3 -m venv .venv
source .venv/bin/activate          # macOS / Linux
# .venv\Scripts\activate           # Windows PowerShell
```

### Step 3 — Install dependencies
```bash
pip install -r requirements.txt
```
This installs FastAPI, NetworkX, the Anthropic SDK, and the file parsers
(openpyxl for XLSX, pypdf for PDF).

### Step 4 — Set your API key as an environment variable
```bash
export ANTHROPIC_API_KEY="sk-ant-...your-key..."     # macOS / Linux
# setx ANTHROPIC_API_KEY "sk-ant-...your-key..."     # Windows (then reopen terminal)
```
To make it stick across terminal sessions on macOS/Linux, add that `export`
line to your `~/.zshrc` or `~/.bashrc`.

**Verify it's set:**
```bash
echo $ANTHROPIC_API_KEY        # should print your key
```

### Step 5 — Run the backend
```bash
uvicorn app.main:app --reload --port 8000
```
On startup it builds the engine. You'll see it come up on
**http://localhost:8000**. Quick checks:
```bash
curl http://localhost:8000/api/health
# {"status":"ok","built":true,"llm":true,"model":"claude-opus-4-7"}
#                                        ^^^^^^ llm:true means your key is live
curl http://localhost:8000/api/ai-status   # shows all 4 agentic roles
```
If `llm` is `false`, your key isn't being read — re-check Step 4 (most often the
key is set in a different terminal than the one running uvicorn).

### Step 6 — Open the dashboard
The dashboard is `frontend/dashboard.html`. Two ways to use it:

**Quick (demo mode):** just double-click `dashboard.html` to open it in your
browser. Everything works; uploads are *simulated* (no backend calls).

**Live mode (real extraction & chaining):** tell the dashboard where your
backend is. Open `frontend/dashboard.html` in a text editor, and right after the
`<body>` tag (or in the browser console before using upload) add:
```html
<script>window.VULNIQ_BACKEND = "http://localhost:8000";</script>
```
Now the Upload tab POSTs real files to your backend, which runs the Extraction
Agent and live re-chaining. The Upload tab shows a green "Live backend connected"
badge when this is working.

> Because browsers block file:// pages from calling localhost in some setups,
> for live mode it's cleanest to serve the frontend too. Use the bundled
> **no-cache** server so your browser always loads the latest dashboard build:
> ```bash
> python3 frontend/serve.py 5500
> ```
> then visit **http://localhost:5500/dashboard.html**. CORS is already enabled
> on the backend. (Plain `python3 -m http.server` also works, but the browser may
> cache an old build — if tabs other than Upload stop reflecting new uploads,
> that's a stale cache; use `serve.py` or hard-reload with **Cmd/Ctrl+Shift+R**.)

---

## Using it

1. Open the **Upload Findings** tab.
2. Drag in scan files from any team — JSON, XML, CSV, XLSX, or PDF.
3. Watch the pipeline: ① format extraction → ② AI normalization → ③ merge +
   recompute chains. Each file shows how many findings were extracted,
   auto-accepted, and flagged for human review (low confidence).
4. Flip to **Attack Chains** / **Priorities** — the newly uploaded findings are
   now chained alongside everything else.
5. Use **Ask VulnIQ** to query, simulate patches, and generate the brief.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `llm: false` in health | Key not set in the terminal running uvicorn. Re-export, restart uvicorn. |
| `CERTIFICATE_VERIFY_FAILED` / errors behind Zscaler or a corporate VPN | An HTTPS-inspecting proxy re-signs traffic with a corporate root your OS trusts but Python's `certifi` doesn't. VulnIQ now verifies against the **OS trust store** via `truststore` (installed from `requirements.txt`) — make sure it's installed (`pip install truststore`) and restart uvicorn; the startup log prints `TLS — os trust store (truststore)`. If your proxy root lives in a PEM file instead, set `export VULNIQ_CA_BUNDLE=/path/to/corp-root.pem`. Last resort for local debugging only: `export VULNIQ_INSECURE_SSL=1` (disables verification). |
| Overview/Priorities/Chains/Brief don't update after an upload, only the Upload tab does | Stale browser cache or an old backend without `/api/snapshot`. Serve via `python3 frontend/serve.py 5500`, hard-reload (**Cmd/Ctrl+Shift+R**), and restart uvicorn so it has the latest endpoints. Use the **↻ Refresh** button in the header to force a live re-pull. |
| `command not found: uvicorn` | Activate the venv (Step 2) and re-run `pip install -r requirements.txt`. |
| PDF upload returns 0 findings | The PDF is a scanned image (no text layer). OCR is a Phase-2 item; export the report as text/CSV for now. |
| Upload tab says "Demo mode" | `window.VULNIQ_BACKEND` not set, or backend not reachable. See Step 6 live mode. |
| Browser blocks localhost calls | Serve the frontend via `python3 -m http.server` (Step 6 note) instead of opening the file directly. |
| Want to run without spending | Just don't set the key. Everything runs in deterministic mode; extraction is rougher and flags everything for review. |

---

## What costs money vs. what's free

- **Free, always:** the whole pipeline in deterministic mode, the dashboard,
  the graph, chains, simulate-patch, the brief.
- **Uses your key (cents):** LLM file extraction quality, semantic ENABLES edge
  inference, LLM chain narratives, and the conversational copilot answers.

Set a $10 cap in the Anthropic console and you're completely safe to experiment.

---

# Deployment modes (persistence)

VulnIQ runs in three modes. The attack-path engine is identical in all three;
only *where data lives* changes.

## 1. Local JSON mode (default, zero infra)
No database. Findings/chains live in memory, seeded from the JSON files in
`backend/data/`. State is lost on restart. This is the original dev workflow.

```bash
cd backend
pip install -r requirements.txt
# DATABASE_URL is NOT set -> JSON/in-memory mode
uvicorn app.main:app --reload --port 8000
# in another shell:
python frontend/serve.py        # http://localhost:5500/dashboard.html
```

## 2. PostgreSQL mode (persistent, no Docker)
Point VulnIQ at any Postgres by setting `DATABASE_URL`. Every sync/upload is
saved as an immutable historical run; data survives restarts.

```bash
cd backend
export DATABASE_URL="postgresql+psycopg2://vulniq:vulniq@localhost:5432/vulniq"
alembic upgrade head          # create the schema
uvicorn app.main:app --reload --port 8000
```
(For a quick local test without Postgres you can even use SQLite:
`export DATABASE_URL="sqlite:////tmp/vulniq.db"`.)

## 3. AWS deployment (EC2 + RDS PostgreSQL)
Production deployment uses an EC2 app host + RDS PostgreSQL, with DB credentials
in AWS Secrets Manager (fetched in code, never written). Everything is scripted
in `deploy/`:

- `deploy/setup_ec2.sh` — provisions Python, nginx, venv+deps, a TLS cert, runs
  `alembic upgrade head`, installs the systemd service, and starts everything.
- `deploy/env.ec2.example` — copy to `/opt/vulniq/backend/.env` and fill in your
  `DB_SECRET_ARN`, `DB_HOST`, region, Snyk + LLM gateway vars (the on-instance
  `.env` is gitignored).
- `deploy/nginx-ec2.conf` — serves the dashboard on 443 and proxies `/api`.
- `deploy/vulniq-api.service` — systemd unit for the FastAPI backend.

```bash
# on the EC2 box, after the code is at /opt/vulniq and backend/.env is filled:
sudo bash deploy/setup_ec2.sh
# then, over the VPN:  https://<EC2-private-IP>/dashboard.html
```
`DATABASE_URL` is assembled in code from Secrets Manager (`ai_config._load_db_secret`)
using the instance role's `secretsmanager:GetSecretValue` — no DB password ever
touches the repo or the env file.

---

# First boot / seeding

On the first start against an empty database, VulnIQ seeds run #1 from the JSON
files (`assets.json`, `synthetic_findings.json`) and marks the DB seeded. After
that the **database is the source of truth** and JSON is never reseeded. On every
later restart the engine is hydrated from the most recent run, so the dashboard
shows your last state immediately.

---

# Backup, restore, disaster recovery

On RDS, prefer **automated backups + snapshots** (enabled at provisioning) — that
covers point-in-time recovery with no extra work. For logical dumps:

**Backup:**
```bash
pg_dump "$DATABASE_URL" > vulniq_backup_$(date +%F).sql
```

**Restore** into a fresh database:
```bash
psql "$DATABASE_URL" < vulniq_backup_YYYY-MM-DD.sql
```

**Schema migration** (after pulling new code with model changes):
```bash
cd backend && alembic upgrade head     # also runs automatically via setup_ec2.sh
```

**Disaster recovery:** rely on RDS automated backups/snapshots; keep periodic
`pg_dump` exports off-host as a belt-and-suspenders. To rebuild: provision a fresh
RDS, run `alembic upgrade head` (creates schema + seeds run #1), then restore the
latest dump.
