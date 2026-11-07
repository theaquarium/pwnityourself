"""PIY orchestration API.

The browser never touches Modal. This FastAPI service holds the Modal token,
spins up a throwaway Sandbox per lab session, and runs the notebook cells'
shell commands inside it on request.
"""
import os

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from piy_lab import LabManager, CapacityError
from lesson import build_lesson

app = FastAPI(title="PIY API")

# The frontend talks to this API same-origin via Next's /api rewrite, so no
# cross-origin access is needed in normal use. Keep the allowlist tight; add
# extra origins via PIY_ALLOWED_ORIGINS (comma-separated) if ever needed.
_default_origins = "http://localhost:3000,http://127.0.0.1:3000"
ALLOWED_ORIGINS = [
    o.strip()
    for o in os.environ.get("PIY_ALLOWED_ORIGINS", _default_origins).split(",")
    if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

manager = LabManager()


class ExecBody(BaseModel):
    command: str
    background: bool = False
    logfile: str | None = None


@app.get("/api/health")
def health():
    return {"ok": True, "sessions": len(manager.sessions)}


@app.get("/api/lesson")
def lesson():
    return build_lesson()


@app.post("/api/session")
def create_session():
    try:
        s = manager.create()
    except CapacityError as e:
        raise HTTPException(status_code=429, detail=str(e))
    return {"session_id": s.id, "timeout": 900}


@app.post("/api/session/{sid}/exec")
def exec_cell(sid: str, body: ExecBody):
    s = manager.get(sid)
    if not s:
        raise HTTPException(status_code=404, detail="session not found (it may have expired)")
    if body.background:
        logfile = body.logfile or "/tmp/bg.log"
        s.exec_background(body.command, logfile)
        return {"stdout": f"[started in background; logs -> {logfile}]\n", "stderr": "", "exit_code": 0}
    return s.exec(body.command)


@app.delete("/api/session/{sid}")
def delete_session(sid: str):
    manager.destroy(sid)
    return {"ok": True}
