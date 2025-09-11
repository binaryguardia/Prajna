Prajna AI
=========

Overview
--------
Prajna AI is a full-stack app that combines natural chat with on-demand Splunk searching and log summarization. It prioritizes being simple and fast:
- Normal chat uses tgpt by default (no API keys needed) with graceful fallback to OpenAI → Gemini.
- Splunk searches are only executed when the user asks for logs.
- Summaries of Splunk results prefer OpenAI → Gemini → tgpt as a fallback.
<img width="1920" height="1080" alt="Screenshot from 2025-09-11 22-49-13" src="https://github.com/user-attachments/assets/f8ad4638-87ef-40db-aa71-9e46afd46e8f" />

One-Command Start
-----------------

Requirements:
- Node.js 18+ and npm
- Optional: tgpt installed locally (recommended), set `TGPT_PATH` if not on PATH

Run:

```bash
./quickstart.sh
```

This will:
- Install backend and frontend dependencies
- Start backend on port 5000
- Start frontend (React) on port 3000
- Print a quick usage guide in the terminal
- Open your browser to the UI

Docker
------

Build and run with Docker Compose:

```bash
docker compose up --build
```

Services:
- Backend available at `http://localhost:5000`
- Frontend available at `http://localhost:3000`

Notes:
- The backend container reads `TGPT_PATH`. If you need tgpt inside the container, bake it into the image or bind-mount the binary path. By default the app prefers tgpt on the host via the quickstart script.
- Splunk env vars can be overridden when running `docker compose`.

Beginner-Friendly Setup
-----------------------

1) Install tgpt (no account needed)
- Linux (Ubuntu/Debian):
  ```bash
  sudo curl -L -o /usr/local/bin/tgpt https://raw.githubusercontent.com/your-org/tgpt-releases/main/tgpt
  sudo chmod +x /usr/local/bin/tgpt
  tgpt --help
  ```
- macOS (Homebrew):
  ```bash
  brew tap your-org/tap
  brew install tgpt
  ```
- Windows:
  - Download `tgpt.exe` from the official release page and add it to your PATH.

If tgpt isn’t on PATH, set:
```bash
export TGPT_PATH=/path/to/tgpt
```

2) (Optional) Add OpenAI or Gemini
- Get your API key from the provider.
- Open Prajna UI → Settings → paste the key and select a model.

3) Basic Splunk configuration (for real logs)
- Install Splunk Enterprise on a VM or local machine.
- Install Splunk Universal Forwarder on the machine that has logs and point it to your Splunk instance.
- Choose logs to forward (e.g., `/var/log/*`).
- In Prajna, adjust env vars if needed: `SPLUNK_HOST`, `SPLUNK_USER`, `SPLUNK_PASS`, `SPLUNK_INDEX`.

Manual Start (alternative)
-------------------------

Backend:
```bash
cd backend
npm install
PORT=5000 node server.js
```

Frontend:
```bash
cd frontend
npm install
npm start
```

Configuration
-------------

Environment variables (optional):
- `PORT` (backend port, default 5000)
- `FRONTEND_PORT` (frontend port, default 3000)
- `TGPT_PATH` (path to tgpt binary)
- `TGPT_TIMEOUT_MS` (default 12000)
- `SPLUNK_HOST`, `SPLUNK_USER`, `SPLUNK_PASS`, `SPLUNK_INDEX` (Splunk REST params)
- `RATE_LIMIT_RPM` (per-IP requests per minute, default 30)
- `MAX_CONCURRENT_OPENAI` (default 2)

Providers
---------
- OpenAI: configure key and model via UI Settings
- Gemini: configure key via UI Settings
- Claude: configure key via UI Settings (future support in summarization)
- tgpt: install locally; no API key needed

Behavior
--------
- Normal chat → tgpt (fallback: OpenAI → Gemini)
- Logs request → Splunk search only when asked, then summarize (OpenAI → Gemini → tgpt)
- Splunk query builder supports: today/yesterday/this week/last N, index/sourcetype/host/source, IPs, CVEs, hashes, ports, HTTP fields. Results capped with `| head 20`.

Security Notes
--------------
- The backend includes basic per-IP rate limiting and a small concurrency queue for OpenAI.
- Do not commit real API keys.

Files To Commit to GitHub
-------------------------
Commit:
- `backend/` (except secrets)
- `frontend/`
- `quickstart.sh`
- `README.md`

Do NOT commit:
- `backend/api_keys.json` (contains keys; keep blank in repo)
- Any `.env` files with secrets
- Local logs: `.backend.log`, `.frontend.log`
- `node_modules/` (use `.gitignore`)

.gitignore Suggestion
---------------------
```
node_modules/
.env
.backend.log
.frontend.log
backend/api_keys.json
```

Troubleshooting
---------------
- UI not opening: open `http://localhost:3000` manually.
- Backend not starting: check `.backend.log`. Verify Node.js v18+.
- tgpt errors: ensure `tgpt` is installed and in PATH, or set `TGPT_PATH`.
- OpenAI/Gemini 429s: enable billing or rely on tgpt.
 - Splunk: ensure Splunk REST (`https://127.0.0.1:8089`) is reachable and that your index has data.

Video Guide
-----------
- Full walkthrough on YouTube: https://youtu.be/your-video-id-here

Authors
-------
- @binaryguardia
- Pradeep Kumar

License
-------
Copyright (c) @binaryguardia, Pradeep Kumar.
All rights reserved.


