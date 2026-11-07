"""Modal session management for PIY, shared across all labs.

This module owns everything that talks to Modal. Each lab (see the `lessons`
package) supplies its own vulnerable-target image; this manager creates one
throwaway Modal Sandbox per user session from the right image and runs the
notebook cells' shell commands inside it.
"""
import os
import time
import uuid
import threading

import modal

from lessons import get_module

SANDBOX_TIMEOUT_DEFAULT = 900  # seconds; box self-destructs after this
# Cap on concurrent live sandboxes across the whole backend. Each sandbox is a
# paid Modal container, so this bounds cost/abuse from anonymous callers.
MAX_CONCURRENT_SESSIONS = int(os.environ.get("PIY_MAX_SESSIONS", "25"))


class CapacityError(Exception):
    """Raised when the concurrent-session cap is reached."""


class UnknownLabError(Exception):
    """Raised when a session is requested for a lab slug we don't have."""


class LabSession:
    """Wraps one Modal Sandbox for one user's lab session."""

    def __init__(self, module, app, image):
        self.id = uuid.uuid4().hex[:12]
        self.slug = module.SLUG
        self._lock = threading.Lock()
        self.created_at = time.time()
        self.timeout = getattr(module, "SANDBOX_TIMEOUT", SANDBOX_TIMEOUT_DEFAULT)
        self.expires_at = self.created_at + self.timeout
        self.sandbox = modal.Sandbox.create(
            "sleep", "infinity", image=image, app=app, timeout=self.timeout
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
        self.sessions: dict[str, LabSession] = {}
        self._pending = 0  # slots reserved by in-flight create() calls
        self._lock = threading.Lock()
        # Per-lab Modal app + image, built lazily and reused across sessions.
        self._apps: dict[str, modal.App] = {}
        self._images: dict[str, modal.Image] = {}
        self._res_lock = threading.Lock()

    def _resources(self, module):
        with self._res_lock:
            app = self._apps.get(module.APP_NAME)
            if app is None:
                app = modal.App.lookup(module.APP_NAME, create_if_missing=True)
                self._apps[module.APP_NAME] = app
            image = self._images.get(module.SLUG)
            if image is None:
                image = module.build_image()
                self._images[module.SLUG] = image
            return app, image

    def _prune_locked(self):
        """Drop and terminate expired sessions. Caller holds self._lock."""
        for sid in [s for s, sess in self.sessions.items() if sess.is_expired()]:
            sess = self.sessions.pop(sid, None)
            if sess:
                sess.terminate()

    def create(self, slug: str) -> LabSession:
        module = get_module(slug)
        if module is None:
            raise UnknownLabError(slug)
        # Reserve a slot under the lock BEFORE the slow Sandbox.create so
        # concurrent bursts cannot collectively exceed the cap (live sessions
        # plus in-flight creations are both counted).
        with self._lock:
            self._prune_locked()
            if len(self.sessions) + self._pending >= MAX_CONCURRENT_SESSIONS:
                raise CapacityError(
                    f"server at capacity ({MAX_CONCURRENT_SESSIONS} live labs); try again shortly"
                )
            self._pending += 1
        # Create outside the lock: Sandbox.create is slow (network) and must not
        # block other requests. The reservation above holds our slot meanwhile.
        try:
            app, image = self._resources(module)
            s = LabSession(module, app, image)
        except Exception:
            with self._lock:
                self._pending -= 1
            raise
        with self._lock:
            self._pending -= 1
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
