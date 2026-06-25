"""
In-process manager for the vendor HUD FastAPI servers.

Instead of spawning `python -m nethuds.<vendor>.server` subprocesses (what the
CLI launcher does), the desktop app imports each vendor's FastAPI `app` and runs
it on a background thread via uvicorn, bound to 127.0.0.1 only. This gives us:

  * direct control of the bound port (no env-var/argv plumbing into a subprocess);
  * no listening socket on 0.0.0.0 (the servers open SSH sessions with stored
    creds -- they must not be reachable off-box on a laptop);
  * lifecycle tied to the app: close the window, the servers die with it.

Servers are started lazily -- a vendor only spins up when its first tab opens.

Because every vendor index.html derives its WebSocket origin from
`location.host`, the frontend needs no knowledge of which port it landed on;
serving it from the chosen port is sufficient.
"""

from __future__ import annotations

import atexit
import importlib
import logging
import os
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("nethuds.desktop.servers")

# Make a vendored copy of the nethuds package importable as top-level
# `nethuds`. This supports a layout where nethuds/ is shipped *inside* the
# desktop project (e.g. nhd/nethuds/) rather than pip-installed. If no such
# directory sits next to this module, sys.path is left untouched and an
# installed `nethuds` is used instead. Walk up a couple of levels so it works
# whether this file lives at the project root or one package deep.
def _ensure_nethuds_importable() -> None:
    import sys
    from pathlib import Path
    here = Path(__file__).resolve().parent
    for base in (here, here.parent, here.parent.parent):
        if (base / "nethuds" / "__init__.py").is_file():
            if str(base) not in sys.path:
                sys.path.insert(0, str(base))
            return


_ensure_nethuds_importable()

# vendor key -> (module exposing FastAPI `app`, preferred port)
VENDOR_MODULES: dict[str, tuple[str, int]] = {
    "arista":  ("nhd.nethuds.arista.server", 8470),
    "juniper": ("nhd.nethuds.juniper.server", 8471),
    "cisco":   ("nhd.nethuds.cisco_ios.server", 8472),
    "linux":   ("nhd.nethuds.linux.server", 8478),
}

# Vendors run as a subprocess per tab instead of a shared in-process thread.
# These servers keep per-device state in MODULE-LEVEL globals (CONFIG["device"],
# collector, poll_task), so two tabs in the same process would collide — a
# second /api/connect hot-swaps the global target out from under the first. A
# separate OS process gives each tab its own globals and event loop. The session
# vendors (arista/juniper/cisco) isolate devices by session_id within one
# server, so they stay shared.
DEDICATED_VENDORS = {"linux"}


def find_free_port(preferred: int, host: str = "127.0.0.1", span: int = 50) -> int:
    """Return `preferred` if bindable, else walk forward; fall back to ephemeral.

    Note: there is an unavoidable TOCTOU gap between releasing this probe socket
    and uvicorn binding it. On loopback for a single desktop user that race is
    not worth guarding against.
    """
    for port in range(preferred, preferred + span):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((host, port))
                return port
            except OSError:
                continue
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


class _UvicornThread(threading.Thread):
    def __init__(self, app, host: str, port: int):
        super().__init__(daemon=True, name=f"uvicorn-{port}")
        import uvicorn  # lazy: keeps this module importable without web deps
        config = uvicorn.Config(
            app, host=host, port=port, log_level="warning", lifespan="on",
        )
        self.server = uvicorn.Server(config)
        # We run off the main thread; uvicorn's signal handlers would raise
        # "set_wakeup_fd only works in main thread". Disable them.
        self.server.install_signal_handlers = lambda: None

    def run(self):
        self.server.run()

    def stop(self, timeout: float = 5.0):
        self.server.should_exit = True
        self.join(timeout=timeout)


@dataclass
class RunningServer:
    vendor: str
    host: str
    port: int
    thread: _UvicornThread | None = None
    proc: subprocess.Popen | None = None

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def is_alive(self) -> bool:
        if self.thread is not None:
            return self.thread.is_alive()
        if self.proc is not None:
            return self.proc.poll() is None
        return False

    def stop(self, timeout: float = 5.0):
        if self.thread is not None:
            self.thread.stop(timeout)
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                try:
                    self.proc.wait(timeout=timeout)
                except Exception:
                    pass


class ServerManager:
    """Owns the vendor HUD servers.

    Session vendors (arista/juniper/cisco) share one in-process thread server
    each. Dedicated vendors (linux) get a fresh subprocess per tab so their
    module-level globals can't collide — see DEDICATED_VENDORS.
    """

    def __init__(self, host: str = "127.0.0.1"):
        self.host = host
        self._shared: dict[str, RunningServer] = {}    # vendor -> shared server
        self._dedicated: list[RunningServer] = []       # per-tab subprocesses
        self._lock = threading.Lock()
        atexit.register(self.stop_all)                  # reap subprocesses on exit

    def _start_thread(self, vendor: str) -> RunningServer:
        """Start a shared in-process server for `vendor` (caller holds lock)."""
        mod_path, preferred = VENDOR_MODULES[vendor]
        module = importlib.import_module(mod_path)
        app = getattr(module, "app")
        port = find_free_port(preferred, self.host)
        thread = _UvicornThread(app, self.host, port)
        thread.start()
        rs = RunningServer(vendor, self.host, port, thread=thread)
        logger.info("Started %s HUD on %s", vendor, rs.base_url)
        return rs

    def _start_subprocess(self, vendor: str) -> RunningServer:
        """Start a dedicated subprocess running `vendor`'s app on its own port.

        The module path and package root are derived from the actually-imported
        module, so this works whether nethuds is pip-installed or vendored under
        the project (the child gets the right PYTHONPATH either way).
        """
        mod_path, preferred = VENDOR_MODULES[vendor]
        module = importlib.import_module(mod_path)          # validate + resolve
        dotted = module.__name__                            # canonical dotted path
        top = importlib.import_module(dotted.split(".")[0])  # top-level package
        root = Path(top.__file__).resolve().parent.parent   # dir to put on path

        port = find_free_port(preferred, self.host)
        env = dict(os.environ)                              # inherits NETHUDS_CONFIG_DIR
        env["PYTHONPATH"] = os.pathsep.join(
            p for p in (str(root), env.get("PYTHONPATH", "")) if p
        )
        code = (
            "import uvicorn;"
            f"from {dotted} import app;"
            f"uvicorn.run(app, host={self.host!r}, port={port}, log_level='warning')"
        )
        proc = subprocess.Popen([sys.executable, "-c", code], env=env)
        rs = RunningServer(vendor, self.host, port, proc=proc)
        logger.info("Started %s HUD subprocess pid=%s on %s",
                    vendor, proc.pid, rs.base_url)
        return rs

    def acquire(self, vendor: str, wait_ready: float = 10.0) -> RunningServer:
        """Return a server for `vendor`.

        Dedicated vendors get a fresh subprocess the caller must release(); the
        rest reuse a shared in-process server.
        """
        if vendor not in VENDOR_MODULES:
            raise ValueError(f"Unknown vendor '{vendor}'")
        if vendor in DEDICATED_VENDORS:
            rs = self._start_subprocess(vendor)
            with self._lock:
                self._dedicated.append(rs)
        else:
            with self._lock:
                rs = self._shared.get(vendor)
                if rs and rs.is_alive():
                    return rs
                rs = self._start_thread(vendor)
                self._shared[vendor] = rs
        self._wait_ready(rs, wait_ready)
        return rs

    def release(self, rs: RunningServer | None):
        """Stop a dedicated subprocess. No-op for shared servers (kept warm)."""
        if rs is None:
            return
        with self._lock:
            if rs in self._dedicated:
                self._dedicated.remove(rs)
            else:
                return
        logger.info("Stopping %s HUD subprocess pid=%s on %s",
                    rs.vendor, rs.proc.pid if rs.proc else "?", rs.base_url)
        rs.stop()

    def _wait_ready(self, rs: RunningServer, timeout: float) -> bool:
        import urllib.request
        deadline = time.time() + timeout
        url = f"{rs.base_url}/"
        while time.time() < deadline:
            if rs.proc is not None and rs.proc.poll() is not None:
                logger.error("%s HUD subprocess exited early (code %s)",
                             rs.vendor, rs.proc.returncode)
                return False
            try:
                with urllib.request.urlopen(url, timeout=1.0):
                    return True
            except Exception:
                time.sleep(0.15)
        logger.warning("%s HUD not ready after %ss", rs.vendor, timeout)
        return False

    def stop_all(self):
        with self._lock:
            servers = list(self._shared.values()) + list(self._dedicated)
            self._shared.clear()
            self._dedicated.clear()
        for rs in servers:
            logger.info("Stopping %s HUD on %s", rs.vendor, rs.base_url)
            rs.stop()