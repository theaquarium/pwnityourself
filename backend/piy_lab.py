"""Shared Modal lab definition and session wrapper for PIY (Pwn It Yourself).

This module owns everything that talks to Modal: the lab image (an intentionally
vulnerable Log4Shell target plus the attacker tooling, all pre-compiled) and a
LabSession wrapper around a single throwaway Modal Sandbox.
"""
import os
import time
import uuid
import threading
import modal

LAB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lab")
LAB_DIR = os.path.abspath(LAB_DIR)

# Classpaths inside the sandbox.
VICTIM_CP = "/lab/build:/lab/jars/*:/lab/config"
ATTACKER_CP = "/lab/build:/lab/jars/*"

image = (
    modal.Image.from_registry("openjdk:8u181-jdk-stretch", add_python=None)
    .add_local_dir(os.path.join(LAB_DIR, "jars"), "/lab/jars", copy=True)
    .add_local_dir(os.path.join(LAB_DIR, "src"), "/lab/src", copy=True)
    .run_commands(
        "mkdir -p /lab/build /lab/www /lab/config",
        "cp /lab/src/log4j2.xml /lab/config/",
        "javac -cp '/lab/jars/*' -d /lab/build /lab/src/VulnerableApp.java",
        "javac -cp '/lab/jars/*' -d /lab/build /lab/src/LDAPRefServer.java /lab/src/FileServer.java",
        "javac -d /lab/www /lab/src/Exploit.java",
    )
)

SANDBOX_TIMEOUT = 900  # seconds; box self-destructs after this
# Cap on concurrent live sandboxes across the whole backend. Each sandbox is a
# paid Modal container, so this bounds cost/abuse from anonymous callers.
MAX_CONCURRENT_SESSIONS = int(os.environ.get("PIY_MAX_SESSIONS", "25"))


class CapacityError(Exception):
    """Raised when the concurrent-session cap is reached."""


class LabSession:
    """Wraps one Modal Sandbox for one user's lab session."""

    def __init__(self, app):
        self.id = uuid.uuid4().hex[:12]
        self._app = app
        self._lock = threading.Lock()
        self.created_at = time.time()
        self.expires_at = self.created_at + SANDBOX_TIMEOUT
        self.sandbox = modal.Sandbox.create(
            "sleep", "infinity", image=image, app=app, timeout=SANDBOX_TIMEOUT
        )

    def is_expired(self) -> bool:
        return time.time() >= self.expires_at

    def exec(self, command: str, timeout: int = 60):
        """Run a shell command in the sandbox and return combined result."""
        with self._lock:
            p = self.sandbox.exec("bash", "-c", command, timeout=timeout)
            p.wait()
            return {
                "stdout": p.stdout.read(),
                "stderr": p.stderr.read(),
                "exit_code": p.returncode,
            }

    def exec_background(self, command: str, logfile: str):
        """Launch a long-running server detached; logs go to `logfile`."""
        wrapped = f"( {command} > {logfile} 2>&1 & ) ; echo started"
        return self.exec(wrapped, timeout=15)

    def terminate(self):
        try:
            self.sandbox.terminate()
        except Exception:
            pass


class LabManager:
    def __init__(self):
        self.app = modal.App.lookup("piy-log4shell", create_if_missing=True)
        self.sessions: dict[str, LabSession] = {}
        self._lock = threading.Lock()

    def _prune_locked(self):
        """Drop and terminate expired sessions. Caller holds the lock."""
        for sid in [s for s, sess in self.sessions.items() if sess.is_expired()]:
            sess = self.sessions.pop(sid, None)
            if sess:
                sess.terminate()

    def create(self) -> LabSession:
        with self._lock:
            self._prune_locked()
            if len(self.sessions) >= MAX_CONCURRENT_SESSIONS:
                raise CapacityError(
                    f"server at capacity ({MAX_CONCURRENT_SESSIONS} live labs); try again shortly"
                )
        # Create outside the lock: Sandbox.create is slow (network) and must not
        # block other requests. The cap above may be briefly exceeded under a
        # burst, which is acceptable for a soft cost guard.
        s = LabSession(self.app)
        with self._lock:
            self.sessions[s.id] = s
        return s

    def get(self, sid: str) -> LabSession | None:
        with self._lock:
            s = self.sessions.get(sid)
            if s and s.is_expired():
                self.sessions.pop(sid, None)
                s.terminate()
                return None
            return s

    def destroy(self, sid: str):
        with self._lock:
            s = self.sessions.pop(sid, None)
        if s:
            s.terminate()
