# PIY — Pwn It Yourself

Interactive, hands-on walkthroughs of real software exploits. Each lesson is a
notebook-style article that spins up a **real, deliberately-vulnerable target**
in an isolated [Modal](https://modal.com) sandbox and lets you fire the exploit
yourself, step by step, and watch the victim execute your commands.

First lesson: **Log4Shell (CVE-2021-44228)**.

## How it works

```
Browser (Next.js notebook UI)
   │  same-origin /api/* (Next rewrite)
   ▼
FastAPI orchestration API  (holds the Modal token)
   │  Modal SDK
   ▼
Modal Sandbox  (gVisor-isolated, one per session, self-destructs on timeout)
   • custom image: old JDK8 + vulnerable Log4j app + attacker tooling, pre-compiled
```

The browser never talks to Modal directly. The FastAPI service creates one
throwaway sandbox per lab session and runs each notebook cell's shell command
inside it via `Sandbox.exec`, streaming output back to the page.

## Layout

- `lab/` — the exploit lab: vulnerable app + attacker sources (`src/`), the
  trusted jars baked into the image (`jars/`), and a standalone end-to-end
  validation script (`exploit_lab.py`).
- `backend/` — FastAPI app (`main.py`), the Modal image + session manager
  (`piy_lab.py`), and the lesson content (`lesson.py`).
- `frontend/` — Next.js (App Router) notebook-style UI.

## Running locally

Prerequisites: Python 3.11+, Node 20+, a Modal account + token
(`modal token set ...`).

```bash
# 1. backend (serves on :8000)
cd backend
pip install -r requirements.txt
python -m uvicorn main:app --port 8000

# 2. frontend (serves on :3000, proxies /api -> :8000)
cd frontend
npm install
npm run dev
```

Open http://localhost:3000, click **Start lab**, and run the steps.

## Security notes

This project intentionally runs exploitable software. All of it executes inside
ephemeral, network-isolated Modal sandboxes (gVisor), one per session, with a
hard timeout. The exploit traffic stays on `127.0.0.1` inside the sandbox.
