#!/usr/bin/env bash
set -euo pipefail

# Prajna AI One-Command Starter
# Authors: binaryguardia, Pradeep Kumar

BACKEND_PORT=${PORT:-5000}
FRONTEND_PORT=${FRONTEND_PORT:-3000}
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"
FRONTEND_DIR="$ROOT_DIR/frontend"

BLUE='\033[1;34m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'; RED='\033[1;31m'; NC='\033[0m'

banner() {
  echo -e "${BLUE}==========================================${NC}"
  echo -e "${GREEN}        Prajna AI - One Command Start     ${NC}"
  echo -e "${BLUE}==========================================${NC}"
}

open_browser() {
  local url="$1"
  if command -v xdg-open >/dev/null 2>&1; then xdg-open "$url" >/dev/null 2>&1 || true; fi
}

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo -e "${RED}Missing dependency:${NC} $1"
    echo -e "Installing Node.js (v18+ recommended) and npm."
    apt install npm
    echo -e "Instaling tgpt..."
    curl -sSL https://raw.githubusercontent.com/aandrew-me/tgpt/main/install | bash -s /usr/local/bin
    exit 1
  fi
}

start_backend() {
  echo -e "${YELLOW}Installing backend deps...${NC}"
  cd "$BACKEND_DIR"
  npm ci || npm install
  echo -e "${YELLOW}Starting backend on :$BACKEND_PORT...${NC}"
  (PORT=$BACKEND_PORT node server.js) > "$ROOT_DIR/.backend.log" 2>&1 &
  BACKEND_PID=$!
  cd "$ROOT_DIR"
}

wait_for_backend() {
  echo -e "${YELLOW}Waiting for backend to be ready...${NC}"
  for i in {1..30}; do
    if curl -s "http://localhost:$BACKEND_PORT/api/system/status" >/dev/null 2>&1; then
      echo -e "${GREEN}Backend is up at http://localhost:$BACKEND_PORT${NC}"
      return 0
    fi
    sleep 1
  done
  echo -e "${RED}Backend did not start within expected time. See .backend.log${NC}"
}

start_frontend() {
  echo -e "${YELLOW}Installing frontend deps...${NC}"
  cd "$FRONTEND_DIR"
  npm ci || npm install
  echo -e "${YELLOW}Starting frontend on :$FRONTEND_PORT...${NC}"
  (BROWSER=none npm start) > "$ROOT_DIR/.frontend.log" 2>&1 &
  FRONTEND_PID=$!
  cd "$ROOT_DIR"
}

trap_ctrl_c() {
  echo -e "\n${YELLOW}Shutting down...${NC}"
  if [[ -n "${FRONTEND_PID:-}" ]]; then kill "$FRONTEND_PID" >/dev/null 2>&1 || true; fi
  if [[ -n "${BACKEND_PID:-}" ]]; then kill "$BACKEND_PID" >/dev/null 2>&1 || true; fi
  exit 0
}
trap trap_ctrl_c INT TERM

print_guide() {
  echo -e "${BLUE}\nQuick Guide:${NC}"
  echo -e "- Backend logs: $ROOT_DIR/.backend.log"
  echo -e "- Frontend logs: $ROOT_DIR/.frontend.log"
  echo -e "- Backend URL: http://localhost:$BACKEND_PORT"
  echo -e "- UI URL: http://localhost:$FRONTEND_PORT"
  echo -e "\nProviders:"
  echo -e "- OpenAI/Gemini/Claude: Configure keys via the UI (Settings)"
  echo -e "- tgpt: Install locally and ensure it's in PATH (or set TGPT_PATH)"
  echo -e "\nUsage:"
  echo -e "- Natural chat uses tgpt by default to avoid quotas"
  echo -e "- Splunk searches run only when you ask for logs"
  echo -e "- Summaries prefer OpenAI → Gemini → tgpt fallback"
  echo -e "\nPress Ctrl+C to stop."
}

banner
need node
need npm

start_backend
wait_for_backend || true
start_frontend

echo -e "${GREEN}Opening UI...${NC}"
open_browser "http://localhost:$FRONTEND_PORT"

print_guide

# Keep script attached so trap works
wait


