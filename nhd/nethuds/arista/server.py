"""
Arista HUD Server
FastAPI backend with WebSocket push for real-time device telemetry.
Session-based multi-user architecture with persistent SSH sessions.
Includes SSH terminal proxy via paramiko -> xterm.js.
"""

import asyncio
import json
import logging
import os
import tempfile
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path

import paramiko
import yaml
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Body, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .collector import AristaCollector

from ..paths import load_yaml_config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("server")

# This server is vendor-locked: its collector/parsers only understand
# arista_eos. device_type is forced to this value so the netmiko driver can
# never diverge from the parsers, regardless of what a client sends.
SERVER_DEVICE_TYPE = "arista_eos"

# ---- Global state ----
CONFIG: dict = {}
SESSION_TTL = 300  # seconds without WS clients before reaping


@dataclass
class Session:
    session_id: str
    device_config: dict
    collector: AristaCollector
    poll_task: asyncio.Task | None = None
    latest_data: dict | None = None
    clients: set = field(default_factory=set)
    created: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    tmp_key_path: str | None = None

    def touch(self):
        self.last_activity = time.time()


sessions: dict[str, Session] = {}


def _get_session(session_id: str | None) -> Session | None:
    if not session_id:
        return None
    s = sessions.get(session_id)
    if s:
        s.touch()
    return s


def load_config() -> dict:
    _example = Path(__file__).parent / "config.example.yaml"
    return load_yaml_config("arista.yaml", _example)


async def _broadcast_session(session: Session, msg: str):
    dead = set()
    for ws in session.clients:
        try:
            await ws.send_text(msg)
        except Exception:
            dead.add(ws)
    session.clients.difference_update(dead)


async def _poll_loop(session_id: str):
    """Background loop: collect data and push to session's WebSocket clients."""
    interval = CONFIG.get("poll_interval", 15)
    logger.info(f"[{session_id[:8]}] Poll loop starting, interval={interval}s")

    while True:
        session = sessions.get(session_id)
        if not session:
            return

        try:
            loop = asyncio.get_running_loop()
            progress_queue = asyncio.Queue()

            def on_progress(key, idx, total, elapsed, phase="done"):
                loop.call_soon_threadsafe(
                    progress_queue.put_nowait,
                    {"_progress": {
                        "command": key,
                        "index": idx,
                        "total": total,
                        "elapsed": round(elapsed, 1),
                        "phase": phase
                    }}
                )

            async def drain_progress():
                while True:
                    msg = await progress_queue.get()
                    if msg is None:
                        break
                    s = sessions.get(session_id)
                    if s:
                        await _broadcast_session(s, json.dumps(msg))

            drain_task = asyncio.create_task(drain_progress())

            data = await loop.run_in_executor(
                None, lambda: session.collector.collect(on_progress=on_progress)
            )
            # Signal drain to stop, then wait
            progress_queue.put_nowait(None)
            await drain_task

            session.latest_data = data
            payload = json.dumps(data, default=str)
            logger.info(f"[{session_id[:8]}] Broadcasting {len(payload)//1024}KB to {len(session.clients)} client(s)")
            await _broadcast_session(session, payload)

        except Exception as e:
            logger.error(f"[{session_id[:8]}] Poll loop error: {e}")

        await asyncio.sleep(interval)


async def _reap_sessions():
    """Remove sessions with no WebSocket clients for SESSION_TTL seconds."""
    while True:
        await asyncio.sleep(60)
        now = time.time()
        stale = [
            sid for sid, s in sessions.items()
            if not s.clients and (now - s.last_activity) > SESSION_TTL
        ]
        for sid in stale:
            s = sessions.pop(sid, None)
            if s:
                logger.info(f"Reaping stale session {sid[:8]}")
                if s.poll_task and not s.poll_task.done():
                    s.poll_task.cancel()
                try:
                    s.collector.disconnect()
                except Exception:
                    pass
                if s.tmp_key_path and os.path.exists(s.tmp_key_path):
                    try:
                        os.unlink(s.tmp_key_path)
                    except Exception:
                        pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start the session reaper on startup."""
    global CONFIG
    CONFIG = load_config()
    reap_task = asyncio.create_task(_reap_sessions())
    logger.info("Arista HUD server started (awaiting /api/connect)")
    yield
    reap_task.cancel()
    # Tear down all sessions on shutdown
    for sid, s in list(sessions.items()):
        if s.poll_task and not s.poll_task.done():
            s.poll_task.cancel()
        try:
            s.collector.disconnect()
        except Exception:
            pass
    sessions.clear()
    logger.info("Arista HUD server stopped")


app = FastAPI(title="Arista HUD", lifespan=lifespan)

# Serve static files (the HUD frontend)
static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/")
async def root():
    """Serve the HUD frontend."""
    index = static_dir / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return {"error": "static/index.html not found"}


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket, session: str | None = Query(None)):
    """WebSocket endpoint for real-time telemetry push."""
    await ws.accept()
    s = _get_session(session)
    if not s:
        await ws.send_text(json.dumps({"error": "invalid or missing session"}))
        await ws.close()
        return

    s.clients.add(ws)
    logger.info(f"[{session[:8]}] WebSocket client connected ({len(s.clients)} total)")

    # Send current data immediately if available
    if s.latest_data:
        try:
            await ws.send_text(json.dumps(s.latest_data, default=str))
        except Exception:
            pass

    try:
        while True:
            msg = await ws.receive_text()
            if msg == "refresh":
                if s.latest_data:
                    await ws.send_text(json.dumps(s.latest_data, default=str))
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning(f"WebSocket error: {e}")
    finally:
        s.clients.discard(ws)
        logger.info(f"[{session[:8]}] WebSocket client disconnected ({len(s.clients)} remaining)")


@app.get("/api/data")
async def get_data(session: str | None = Query(None)):
    """REST fallback for current device state."""
    s = _get_session(session)
    if s and s.latest_data:
        return s.latest_data
    return {"error": "No data collected yet"}


@app.get("/api/status")
async def get_status(session: str | None = Query(None)):
    """Server health check."""
    s = _get_session(session)
    return {
        "status": "ok",
        "session": session,
        "clients": len(s.clients) if s else 0,
        "poll_count": s.collector._collect_count if s else 0,
        "last_error": s.collector._last_error if s else None,
        "hostname": s.device_config.get("host", "unknown") if s else "not connected",
    }


@app.get("/api/defaults")
async def get_defaults():
    """Return config.yaml device defaults for login modal pre-population."""
    dev = CONFIG.get("device") or {}
    return {
        "host":        dev.get("host", ""),
        "username":    dev.get("username", ""),
        "device_type": SERVER_DEVICE_TYPE,
        "use_keys":    dev.get("use_keys", True),
        "key_file":    dev.get("key_file", "~/.ssh/id_rsa"),
        "legacy_ssh":  dev.get("legacy_ssh", False),
        "port":        dev.get("port", 22),
    }


@app.post("/api/connect")
async def connect_device(body: dict = Body(...)):
    """
    Create a new session for the target device.
    Tests SSH connectivity before returning success.
    Tears down old session if session_id is provided in body.
    """
    new_dev = dict(CONFIG.get("device") or {})
    for key in ("host", "username", "password",
                "use_keys", "key_file", "legacy_ssh", "port", "timeout"):
        if key in body and body[key] is not None:
            new_dev[key] = body[key]
    new_dev["device_type"] = SERVER_DEVICE_TYPE  # authoritative; ignore client value

    # Handle uploaded SSH key text — write to secure temp file
    tmp_key_path = None
    key_text = body.get("key_text")
    if key_text:
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".pem", prefix="hud_key_", delete=False
        )
        tmp.write(key_text)
        tmp.close()
        os.chmod(tmp.name, 0o600)
        new_dev["key_file"] = tmp.name
        new_dev["use_keys"] = True
        tmp_key_path = tmp.name
    elif body.get("password"):
        new_dev["use_keys"] = False
        new_dev.pop("key_file", None)

    if not new_dev.get("host"):
        return {"status": "error", "message": "host is required"}
    if not new_dev.get("username"):
        return {"status": "error", "message": "username is required"}

    # Tear down old session if provided
    old_sid = body.get("session_id")
    if old_sid and old_sid in sessions:
        old = sessions.pop(old_sid)
        if old.poll_task and not old.poll_task.done():
            old.poll_task.cancel()
            try:
                await old.poll_task
            except asyncio.CancelledError:
                pass
        try:
            old.collector.disconnect()
        except Exception:
            pass
        if old.tmp_key_path and os.path.exists(old.tmp_key_path):
            try:
                os.unlink(old.tmp_key_path)
            except Exception:
                pass

    # Create collector and test connectivity
    collector = AristaCollector(new_dev)
    try:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, collector.test_connect)
    except Exception as e:
        logger.error(f"Connection test failed for {new_dev['host']}: {e}")
        if tmp_key_path and os.path.exists(tmp_key_path):
            try:
                os.unlink(tmp_key_path)
            except Exception:
                pass
        return {
            "status": "error",
            "message": f"Connection failed: {e}",
        }

    # Create session
    sid = uuid.uuid4().hex
    s = Session(
        session_id=sid,
        device_config=new_dev,
        collector=collector,
        tmp_key_path=tmp_key_path,
    )
    s.poll_task = asyncio.create_task(_poll_loop(sid))
    sessions[sid] = s

    logger.info(f"[{sid[:8]}] Connected to {new_dev['host']} as {new_dev['username']}")
    return {
        "status": "ok",
        "session_id": sid,
        "host": new_dev["host"],
        "username": new_dev["username"],
        "device_type": new_dev.get("device_type", "arista_eos"),
    }


def _open_ssh_shell(cfg: dict, cols: int = 120, rows: int = 36):
    """Open a paramiko interactive shell. Runs in thread pool."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs = {
        "hostname": cfg["host"],
        "username": cfg["username"],
        "timeout": cfg.get("timeout", 45),
        "allow_agent": False,
        "look_for_keys": False,
    }

    key_file = cfg.get("key_file", "")
    if key_file:
        connect_kwargs["key_filename"] = str(Path(key_file).expanduser())
    if cfg.get("password"):
        connect_kwargs["password"] = cfg["password"]

    # Legacy SSH algorithm support
    if cfg.get("legacy_ssh", False):
        connect_kwargs["disabled_algorithms"] = {
            "pubkeys": ["rsa-sha2-256", "rsa-sha2-512"],
        }

    client.connect(**connect_kwargs)
    channel = client.invoke_shell(
        term="xterm-256color", width=cols, height=rows
    )
    channel.settimeout(0.05)
    return client, channel


@app.websocket("/ws/terminal")
async def terminal_ws(ws: WebSocket, session: str | None = Query(None)):
    """WebSocket SSH terminal proxy. Bridges xterm.js <-> paramiko shell."""
    await ws.accept()
    loop = asyncio.get_event_loop()
    s = _get_session(session)
    device_cfg = s.device_config if s else {}
    client = None
    channel = None

    if not device_cfg.get("host"):
        await ws.send_text("\r\n\x1b[31mNo active session\x1b[0m\r\n")
        await ws.close()
        return

    try:
        client, channel = await loop.run_in_executor(
            None, lambda: _open_ssh_shell(device_cfg)
        )
        logger.info(f"Terminal session opened to {device_cfg['host']}")
    except Exception as e:
        logger.error(f"Terminal SSH connect failed: {e}")
        await ws.send_text(f"\r\n\x1b[31mSSH connection failed: {e}\x1b[0m\r\n")
        await ws.close()
        return

    stop = asyncio.Event()

    async def ssh_reader():
        """Read from SSH channel, send to WebSocket."""
        while not stop.is_set():
            try:
                data = await loop.run_in_executor(
                    None, lambda: channel.recv(4096) if channel.recv_ready() else b""
                )
                if data:
                    await ws.send_bytes(data)
                elif channel.exit_status_ready():
                    break
                else:
                    await asyncio.sleep(0.02)
            except Exception:
                break
        stop.set()

    async def ws_reader():
        """Read from WebSocket, send to SSH channel."""
        try:
            while not stop.is_set():
                msg = await ws.receive()
                if msg.get("type") == "websocket.disconnect":
                    break
                data = msg.get("bytes") or (msg.get("text", "").encode())
                if data:
                    # Handle resize messages (JSON with cols/rows)
                    if data[:1] == b"{":
                        try:
                            resize = json.loads(data)
                            if "cols" in resize and "rows" in resize:
                                channel.resize_pty(
                                    width=resize["cols"], height=resize["rows"]
                                )
                                continue
                        except (json.JSONDecodeError, ValueError):
                            pass
                    await loop.run_in_executor(None, channel.send, data)
        except WebSocketDisconnect:
            pass
        except Exception as e:
            logger.warning(f"Terminal WS reader error: {e}")
        stop.set()

    try:
        await asyncio.gather(ssh_reader(), ws_reader())
    finally:
        if channel:
            try:
                channel.close()
            except Exception:
                pass
        if client:
            try:
                client.close()
            except Exception:
                pass
        logger.info("Terminal session closed")


def main():
    cfg = load_config()
    srv = cfg.get("server", {})
    uvicorn.run(
        app,
        host=srv.get("host", "0.0.0.0"),
        port=srv.get("port", 8470),
        ssl_certfile=srv.get("ssl_certfile"),
        ssl_keyfile=srv.get("ssl_keyfile"),
        log_level="info",
    )


if __name__ == "__main__":
    main()
