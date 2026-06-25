"""
Linux HUD Server
FastAPI backend with WebSocket push for real-time device telemetry.
Includes local PTY or SSH terminal proxy via paramiko -> xterm.js.
"""

import asyncio
import fcntl
import json
import logging
import os
import pty
import signal
import struct
import tempfile
import termios
import time
from contextlib import asynccontextmanager
from pathlib import Path

import yaml
import paramiko
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Body
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.websockets import WebSocketState

from .collector import LinuxCollector

from ..paths import load_yaml_config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("server")

# This server is vendor-locked: its collector/parsers only understand
# linux. device_type is forced to this value so the netmiko driver can
# never diverge from the parsers, regardless of what a client sends.
SERVER_DEVICE_TYPE = "linux"

# ── Global state ─────────────────────────────────────────
CONFIG: dict = {}
collector: LinuxCollector | None = None
clients: list[WebSocket] = []
latest_data: dict | None = None
poll_task: asyncio.Task | None = None
ssh_lock: asyncio.Lock | None = None


def load_config() -> dict:
    _example = Path(__file__).parent / "config.example.yaml"
    return load_yaml_config("linux.yaml", _example)


async def _broadcast(payload: str):
    """Send a JSON string to all connected WebSocket clients."""
    dead = []
    for ws in list(clients):
        try:
            await ws.send_text(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in clients:
            clients.remove(ws)
    if dead:
        logger.info(f"Removed {len(dead)} dead client(s)")


async def poll_loop():
    global latest_data
    interval = CONFIG.get("poll_interval", 15)
    logger.info(f"Poll loop starting, interval={interval}s")
    while True:
        if not collector:
            await asyncio.sleep(1)
            continue
        try:
            loop = asyncio.get_running_loop()
            progress_queue = asyncio.Queue()

            # Progress callback — fires from the collector thread,
            # crosses into the event loop via call_soon_threadsafe.
            def on_progress(key, idx, total, elapsed, phase="done"):
                loop.call_soon_threadsafe(
                    progress_queue.put_nowait,
                    {"_progress": {
                        "command": key,
                        "index": idx,
                        "total": total,
                        "elapsed": round(elapsed, 1),
                        "phase": phase,
                    }}
                )

            # Drain progress events and broadcast to clients in real time.
            async def drain_progress():
                while True:
                    msg = await progress_queue.get()
                    if msg is None:
                        break
                    await _broadcast(json.dumps(msg))

            drain_task = asyncio.create_task(drain_progress())

            async with ssh_lock:
                data = await loop.run_in_executor(
                    None,
                    lambda: collector.collect(on_progress=on_progress),
                )

            # Signal drain to stop, then wait for it to finish
            progress_queue.put_nowait(None)
            await drain_task

            latest_data = data
            payload = json.dumps(data, default=str)
            await _broadcast(payload)

        except Exception as e:
            logger.error(f"Poll loop error: {e}")
        await asyncio.sleep(interval)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global CONFIG, poll_task, ssh_lock
    CONFIG = load_config()
    ssh_lock = asyncio.Lock()

    logger.info("Linux HUD server started (awaiting connection)")
    yield
    if poll_task:
        poll_task.cancel()
    logger.info("Linux HUD server stopped")


app = FastAPI(title="Linux HUD", lifespan=lifespan)

static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/")
async def root():
    index = static_dir / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return {"error": "static/index.html not found"}


# ── Telemetry WebSocket ──────────────────────────────────
@app.websocket("/ws")
async def ws_telemetry(ws: WebSocket):
    await ws.accept()
    clients.append(ws)
    logger.info(f"WebSocket client connected ({len(clients)} total)")
    if latest_data:
        try:
            await ws.send_text(json.dumps(latest_data, default=str))
        except Exception:
            pass
    try:
        while True:
            msg = await ws.receive_text()
            if msg == "refresh":
                if latest_data:
                    await ws.send_text(json.dumps(latest_data, default=str))
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning(f"WebSocket error: {e}")
    finally:
        if ws in clients:
            clients.remove(ws)
        logger.info(f"WebSocket client disconnected ({len(clients)} remaining)")


# ── REST endpoints ───────────────────────────────────────
@app.get("/api/data")
async def get_data():
    if latest_data:
        return latest_data
    return {"error": "No data collected yet"}


@app.get("/api/status")
async def get_status():
    return {
        "status": "ok",
        "clients": len(clients),
        "poll_count": collector._collect_count if collector else 0,
        "last_error": collector._last_error if collector else None,
        "hostname": CONFIG.get("device", {}).get("host", "unknown"),
    }


@app.get("/api/defaults")
async def get_defaults():
    """Return config.yaml device defaults for login modal pre-population."""
    dev = CONFIG.get("device", {})
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
    """Hot-swap the collector to a new target device."""
    global CONFIG, collector, poll_task, latest_data

    new_dev = dict(CONFIG.get("device", {}))
    for key in ("host", "username", "password",
                "use_keys", "key_file", "legacy_ssh", "port", "timeout"):
        if key in body and body[key] is not None:
            new_dev[key] = body[key]
    new_dev["device_type"] = SERVER_DEVICE_TYPE  # authoritative; ignore client value

    # Handle uploaded SSH key text — write to secure temp file
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
        new_dev["_tmp_key"] = tmp.name
    elif body.get("password"):
        new_dev["use_keys"] = False
        new_dev.pop("key_file", None)

    if not new_dev.get("host"):
        return {"status": "error", "message": "host is required"}
    if not new_dev.get("username"):
        return {"status": "error", "message": "username is required"}

    if poll_task and not poll_task.done():
        poll_task.cancel()
        try:
            await poll_task
        except asyncio.CancelledError:
            pass

    if collector:
        try:
            collector.disconnect()
        except Exception:
            pass
        old_tmp = CONFIG.get("device", {}).get("_tmp_key")
        if old_tmp and os.path.exists(old_tmp):
            try:
                os.unlink(old_tmp)
            except Exception:
                pass

    latest_data = None

    # Validate SSH connectivity up front, exactly as the session vendors do, so
    # a bad login (or any connect failure) is returned to the caller instead of
    # being swallowed inside poll_loop and surfacing only as a silently empty
    # HUD. test_connect() establishes the persistent session the poll loop then
    # reuses, so this is not a wasted extra connection.
    new_collector = LinuxCollector(new_dev)
    try:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, new_collector.test_connect)
    except Exception as e:
        logger.error(f"Connection test failed for {new_dev['host']}: {e}")
        new_tmp = new_dev.get("_tmp_key")
        if new_tmp and os.path.exists(new_tmp):
            try:
                os.unlink(new_tmp)
            except Exception:
                pass
        collector = None
        poll_task = None
        return {"status": "error", "message": f"Connection failed: {e}"}

    CONFIG["device"] = new_dev
    collector = new_collector
    poll_task = asyncio.create_task(poll_loop())

    logger.info(f"Connected to {new_dev['host']} as {new_dev.get('username', 'local')}")
    return {
        "status": "ok",
        "host": new_dev["host"],
        "username": new_dev.get("username", ""),
        "device_type": new_dev.get("device_type", "linux"),
    }


# ── Terminal WebSocket (local PTY or remote SSH) ─────────
@app.websocket("/ws/terminal")
async def ws_terminal(ws: WebSocket):
    await ws.accept()
    dev = CONFIG.get("device", {})
    host = dev.get("host", "localhost")

    if host in ("localhost", "127.0.0.1", "::1"):
        await _terminal_local(ws)
    else:
        await _terminal_ssh(ws, dev)


async def _terminal_local(ws: WebSocket):
    """Spawn a local bash shell via PTY."""
    pid, fd = pty.openpty()
    child_pid = os.fork()

    if child_pid == 0:
        os.close(pid)
        os.setsid()
        os.dup2(fd, 0)
        os.dup2(fd, 1)
        os.dup2(fd, 2)
        os.close(fd)
        shell = os.environ.get("SHELL", "/bin/bash")
        os.execvp(shell, [shell, "--login"])
    else:
        os.close(fd)
        flags = fcntl.fcntl(pid, fcntl.F_GETFL)
        fcntl.fcntl(pid, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        async def reader():
            while True:
                await asyncio.sleep(0.02)
                try:
                    data = os.read(pid, 4096)
                    if data and ws.client_state == WebSocketState.CONNECTED:
                        await ws.send_bytes(data)
                except (OSError, BlockingIOError):
                    pass
                except Exception:
                    break

        task = asyncio.create_task(reader())
        try:
            while True:
                msg = await ws.receive()
                if "text" in msg:
                    text = msg["text"]
                    try:
                        resize = json.loads(text)
                        if "cols" in resize and "rows" in resize:
                            winsize = struct.pack("HHHH", resize["rows"], resize["cols"], 0, 0)
                            fcntl.ioctl(pid, termios.TIOCSWINSZ, winsize)
                            continue
                    except (json.JSONDecodeError, TypeError):
                        pass
                    os.write(pid, text.encode())
                elif "bytes" in msg:
                    os.write(pid, msg["bytes"])
        except WebSocketDisconnect:
            pass
        finally:
            task.cancel()
            try:
                os.kill(child_pid, signal.SIGTERM)
                os.waitpid(child_pid, 0)
            except Exception:
                pass
            try:
                os.close(pid)
            except Exception:
                pass


async def _terminal_ssh(ws: WebSocket, device_cfg: dict):
    """SSH terminal proxy — mirrors collector auth config exactly."""
    loop = asyncio.get_event_loop()
    client = None
    channel = None

    for attempt in range(3):
        try:
            async with ssh_lock:
                client, channel = await loop.run_in_executor(
                    None, lambda: _open_ssh_shell(device_cfg)
                )
            logger.info(f"Terminal session opened to {device_cfg['host']}")
            break
        except Exception as e:
            logger.warning(f"Terminal SSH attempt {attempt+1}/3 failed: {e}")
            if attempt < 2:
                await ws.send_text(f"\r\n\x1b[33mRetrying SSH ({attempt+2}/3)...\x1b[0m\r\n")
                await asyncio.sleep(2)
            else:
                logger.error(f"Terminal SSH failed after 3 attempts: {e}")
                await ws.send_text(f"\r\n\x1b[31mSSH connection failed: {e}\x1b[0m\r\n")
                await ws.close()
                return

    stop = asyncio.Event()

    async def ssh_reader():
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
        try:
            while not stop.is_set():
                msg = await ws.receive()
                if msg.get("type") == "websocket.disconnect":
                    break
                data = msg.get("bytes") or (msg.get("text", "").encode())
                if data:
                    if data[:1] == b"{":
                        try:
                            resize = json.loads(data)
                            if "cols" in resize and "rows" in resize:
                                channel.resize_pty(width=resize["cols"], height=resize["rows"])
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


def _open_ssh_shell(cfg: dict, cols: int = 120, rows: int = 36):
    """Open paramiko shell using same auth config as the collector."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs = {
        "hostname": cfg["host"],
        "username": cfg.get("username"),
        "timeout": cfg.get("timeout", 30),
        "allow_agent": True,
        "look_for_keys": False,
    }

    if cfg.get("use_keys", False):
        connect_kwargs["look_for_keys"] = True
        key_file = cfg.get("key_file", "")
        if key_file:
            connect_kwargs["key_filename"] = str(Path(key_file).expanduser())
    if cfg.get("password"):
        connect_kwargs["password"] = cfg["password"]

    client.connect(**connect_kwargs)

    channel = client.invoke_shell(term="xterm-256color", width=cols, height=rows)
    channel.settimeout(0.05)

    return client, channel


def main():
    cfg = load_config()
    srv = cfg.get("server", {})
    uvicorn.run(
        app,
        host=srv.get("host", "0.0.0.0"),
        port=srv.get("port", 8478),
        ssl_certfile=srv.get("ssl_certfile"),
        ssl_keyfile=srv.get("ssl_keyfile"),
        log_level="info",
    )


if __name__ == "__main__":
    main()