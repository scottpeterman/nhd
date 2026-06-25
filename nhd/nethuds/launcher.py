"""
HUD Launcher — Service Manager & Device Selector
Manages the 4 vendor HUD server processes and serves a device
selector UI that builds connect URLs for each device.
"""

import asyncio
import json
import logging
import os
import re
import signal
import subprocess
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import uvicorn
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .paths import config_dir, load_yaml_config, save_yaml_config
from .bootstrap import seed_config_dir

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("launcher")

# ---- State ----
CONFIG: dict = {}
DEVICES_EXAMPLE = Path(__file__).parent / "devices.example.yaml"
server_procs: dict[str, subprocess.Popen] = {}
server_status: dict[str, dict] = {}
server_logs: dict[str, list[str]] = {}
MAX_LOG_LINES = 80
clients: set[WebSocket] = set()
health_task: asyncio.Task | None = None

# Pending actions: key -> {"action": "start"|"stop"|"restart", "at": timestamp}
pending_actions: dict[str, dict] = {}
PENDING_TTL = 15  # seconds before a pending action is considered stale

# Map device_type to server key
DTYPE_TO_SERVER = {
    "arista_eos": "arista",
    "juniper_junos": "juniper",
    "cisco_ios": "cisco",
    "linux": "linux",
}

# ---- Platform detection for SC topology import ----
PLATFORM_PATTERNS = [
    (re.compile(r"arista|eos|dcs-|veos", re.I), "arista_eos"),
    (re.compile(r"juniper|junos|mx\d|qfx|ex\d|srx|vmx|acx", re.I), "juniper_junos"),
    (re.compile(r"cisco|ios|nx-os|nexus|catalyst|asr|isr|ws-c|c9[0-9]", re.I), "cisco_ios"),
    (re.compile(r"linux|ubuntu|debian|centos|rhel|cumulus|vyos|alpine", re.I), "linux"),
]


def detect_device_type(platform: str) -> str:
    """Infer Netmiko device_type from a Secure Cartography platform string."""
    for pattern, dtype in PLATFORM_PATTERNS:
        if pattern.search(platform):
            return dtype
    return "linux"  # safe default


def load_config() -> dict:
    """Load live devices.yaml from the config dir, else the packaged example."""
    return load_yaml_config("devices.yaml", DEVICES_EXAMPLE)


def save_config():
    """Persist current CONFIG to the writable config dir."""
    cfg_path = save_yaml_config("devices.yaml", CONFIG)
    logger.info(f"Config saved to {cfg_path}")


def start_server(key: str) -> bool:
    """Start a vendor HUD server as a subprocess."""
    if key in server_procs and server_procs[key].poll() is None:
        logger.warning(f"Server '{key}' already running (PID {server_procs[key].pid})")
        return False

    srv = CONFIG["servers"].get(key)
    if not srv:
        logger.error(f"Unknown server key: {key}")
        return False

    module = srv.get("module")
    if not module:
        logger.error(f"Server '{key}' has no 'module' defined in devices.yaml")
        return False

    server_logs[key] = []
    try:
        proc = subprocess.Popen(
            [sys.executable, "-m", module],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        server_procs[key] = proc
        logger.info(f"Started server '{key}' (PID {proc.pid}) via -m {module}")

        # Start log reader task
        asyncio.get_event_loop().create_task(_read_proc_output(key, proc))
        return True
    except Exception as e:
        logger.error(f"Failed to start '{key}': {e}")
        return False


async def _read_proc_output(key: str, proc: subprocess.Popen):
    """Read subprocess stdout in background and buffer lines."""
    loop = asyncio.get_event_loop()
    try:
        while proc.poll() is None:
            line = await loop.run_in_executor(None, proc.stdout.readline)
            if line:
                line = line.rstrip()
                if key not in server_logs:
                    server_logs[key] = []
                server_logs[key].append(line)
                if len(server_logs[key]) > MAX_LOG_LINES:
                    server_logs[key] = server_logs[key][-MAX_LOG_LINES:]
    except Exception:
        pass


def stop_server(key: str) -> bool:
    """Stop a running vendor HUD server."""
    proc = server_procs.get(key)
    if not proc or proc.poll() is not None:
        logger.warning(f"Server '{key}' not running")
        server_procs.pop(key, None)
        return False

    logger.info(f"Stopping server '{key}' (PID {proc.pid})")
    try:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
        server_procs.pop(key, None)
        return True
    except Exception as e:
        logger.error(f"Failed to stop '{key}': {e}")
        return False


async def health_check_loop():
    """Periodically check each server's /api/status and push to clients."""
    while True:
        try:
            now = time.time()

            # Expire stale pending actions
            stale = [k for k, v in pending_actions.items()
                     if now - v["at"] > PENDING_TTL]
            for k in stale:
                pending_actions.pop(k, None)

            async with httpx.AsyncClient() as client:
                for key, srv in CONFIG.get("servers", {}).items():
                    port = srv["port"]
                    proc = server_procs.get(key)
                    pid = proc.pid if proc and proc.poll() is None else None
                    running = pid is not None

                    # Clear pending action if state matches expectation
                    pa = pending_actions.get(key)
                    if pa:
                        if pa["action"] == "start" and running:
                            pending_actions.pop(key, None)
                        elif pa["action"] == "stop" and not running:
                            pending_actions.pop(key, None)
                        elif pa["action"] == "restart" and running:
                            pending_actions.pop(key, None)

                    status = {
                        "key": key,
                        "label": srv.get("label", key.upper()),
                        "port": port,
                        "module": srv.get("module", ""),
                        "pid": pid,
                        "process_running": running,
                        "reachable": False,
                        "poll_count": 0,
                        "clients": 0,
                        "last_error": None,
                        "hostname": "",
                        "checked_at": now,
                        "pending": pending_actions.get(key),
                        "log_tail": server_logs.get(key, [])[-20:],
                    }

                    if running:
                        try:
                            r = await client.get(
                                f"http://127.0.0.1:{port}/api/status",
                                timeout=3.0,
                            )
                            d = r.json()
                            status["reachable"] = True
                            status["poll_count"] = d.get("poll_count", 0)
                            status["clients"] = d.get("clients", 0)
                            status["last_error"] = d.get("last_error")
                            status["hostname"] = d.get("hostname", "")
                        except Exception:
                            pass

                    server_status[key] = status

            await _broadcast_status()
        except Exception as e:
            logger.error(f"Health check error: {e}")

        await asyncio.sleep(8)


async def _broadcast_status():
    payload = json.dumps({
        "type": "status",
        "servers": list(server_status.values()),
        "timestamp": time.time(),
    })
    dead = set()
    for ws in clients:
        try:
            await ws.send_text(payload)
        except Exception:
            dead.add(ws)
    clients.difference_update(dead)


async def _broadcast_config():
    """Push updated config to all connected clients."""
    payload = json.dumps({
        "type": "config",
        "servers": CONFIG.get("servers", {}),
        "devices": CONFIG.get("devices", []),
        "dtype_map": DTYPE_TO_SERVER,
    })
    dead = set()
    for ws in clients:
        try:
            await ws.send_text(payload)
        except Exception:
            dead.add(ws)
    clients.difference_update(dead)


def parse_sc_topology(topo_data: dict, default_username: str = "admin",
                      group: str = "IMPORTED") -> list[dict]:
    """
    Parse a Secure Cartography topology.json into HUD device entries.

    SC format:
    {
      "<device_name>": {
        "node_details": {
          "ip": "<ip>",
          "platform": "<platform string>"
        },
        "peers": { ... }
      }
    }
    """
    devices = []
    seen_hosts = set()

    for device_name, device_data in topo_data.items():
        node = device_data.get("node_details", {})
        ip = node.get("ip", "")
        platform = node.get("platform", "")

        if not ip or ip in seen_hosts:
            continue
        seen_hosts.add(ip)

        dtype = detect_device_type(platform)

        devices.append({
            "name": device_name,
            "host": ip,
            "username": default_username,
            "device_type": dtype,
            "platform": platform,
            "group": group,
            "tags": ["sc-import"],
        })

    return devices


@asynccontextmanager
async def lifespan(app: FastAPI):
    global CONFIG, health_task
    if os.environ.get("NETHUDS_NO_AUTOSEED", "").lower() not in ("1", "true", "yes"):
        seeded = seed_config_dir()
        if seeded:
            logger.info(f"Seeded {len(seeded)} config file(s) into {config_dir()}")
    CONFIG = load_config()
    logger.info(f"Loaded config: {len(CONFIG.get('servers', {}))} servers, "
                f"{len(CONFIG.get('devices', []))} devices")
    health_task = asyncio.create_task(health_check_loop())
    logger.info("HUD Launcher started on port 8400")
    yield
    # Cleanup: stop all servers
    for key in list(server_procs.keys()):
        stop_server(key)
    if health_task:
        health_task.cancel()
    logger.info("HUD Launcher stopped")


app = FastAPI(title="HUD Launcher", lifespan=lifespan)

static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/")
async def root():
    index = static_dir / "launcher.html"
    if index.exists():
        return FileResponse(str(index))
    return {"error": "launcher.html not found"}


@app.get("/api/config")
async def get_config():
    """Return devices + server definitions for the UI."""
    return {
        "servers": CONFIG.get("servers", {}),
        "devices": CONFIG.get("devices", []),
        "dtype_map": DTYPE_TO_SERVER,
    }


@app.post("/api/server/{key}/start")
async def api_start(key: str):
    pending_actions[key] = {"action": "start", "at": time.time()}
    ok = start_server(key)
    if not ok:
        pending_actions.pop(key, None)
    return {"status": "ok" if ok else "error", "key": key,
            "pending": pending_actions.get(key)}


@app.post("/api/server/{key}/stop")
async def api_stop(key: str):
    pending_actions[key] = {"action": "stop", "at": time.time()}
    ok = stop_server(key)
    if not ok:
        pending_actions.pop(key, None)
    return {"status": "ok" if ok else "error", "key": key,
            "pending": pending_actions.get(key)}


@app.post("/api/server/{key}/restart")
async def api_restart(key: str):
    pending_actions[key] = {"action": "restart", "at": time.time()}
    stop_server(key)
    await asyncio.sleep(0.5)
    ok = start_server(key)
    if not ok:
        pending_actions.pop(key, None)
    return {"status": "ok" if ok else "error", "key": key,
            "pending": pending_actions.get(key)}


@app.get("/api/server/{key}/logs")
async def api_logs(key: str):
    return {"key": key, "lines": server_logs.get(key, [])}


@app.post("/api/devices/import")
async def api_import_devices(request: Request):
    """
    Import devices from a Secure Cartography topology JSON file.

    Accepts: { "topology": { ... SC format ... },
               "username": "admin",
               "group": "IMPORTED",
               "merge": true }
    """
    body = await request.json()
    topo = body.get("topology")
    if not topo or not isinstance(topo, dict):
        return JSONResponse({"error": "Missing or invalid 'topology' object"},
                            status_code=400)

    username = body.get("username", "admin")
    group = body.get("group", "IMPORTED")
    merge = body.get("merge", True)

    imported = parse_sc_topology(topo, default_username=username, group=group)
    if not imported:
        return JSONResponse({"error": "No valid devices found in topology"},
                            status_code=400)

    if merge:
        # Deduplicate by host IP
        existing_hosts = {d["host"] for d in CONFIG.get("devices", [])}
        new_devices = [d for d in imported if d["host"] not in existing_hosts]
        CONFIG.setdefault("devices", []).extend(new_devices)
        added = len(new_devices)
        skipped = len(imported) - added
    else:
        # Remove previous SC imports in this group, then add
        CONFIG["devices"] = [
            d for d in CONFIG.get("devices", [])
            if d.get("group") != group or "sc-import" not in (d.get("tags") or [])
        ]
        CONFIG["devices"].extend(imported)
        added = len(imported)
        skipped = 0

    save_config()
    await _broadcast_config()

    return {
        "status": "ok",
        "added": added,
        "skipped": skipped,
        "total_devices": len(CONFIG["devices"]),
    }


@app.post("/api/devices/clear-import")
async def api_clear_import(request: Request):
    """Remove all SC-imported devices (tagged with sc-import)."""
    body = await request.json() if request.headers.get("content-length", "0") != "0" else {}
    group = body.get("group")

    before = len(CONFIG.get("devices", []))
    if group:
        CONFIG["devices"] = [
            d for d in CONFIG.get("devices", [])
            if not (d.get("group") == group and "sc-import" in (d.get("tags") or []))
        ]
    else:
        CONFIG["devices"] = [
            d for d in CONFIG.get("devices", [])
            if "sc-import" not in (d.get("tags") or [])
        ]

    removed = before - len(CONFIG["devices"])
    save_config()
    await _broadcast_config()

    return {"status": "ok", "removed": removed,
            "total_devices": len(CONFIG["devices"])}


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    clients.add(ws)
    logger.info(f"Launcher client connected ({len(clients)} total)")

    # Send config + current status immediately
    await ws.send_text(json.dumps({
        "type": "config",
        "servers": CONFIG.get("servers", {}),
        "devices": CONFIG.get("devices", []),
        "dtype_map": DTYPE_TO_SERVER,
    }))
    if server_status:
        await ws.send_text(json.dumps({
            "type": "status",
            "servers": list(server_status.values()),
            "timestamp": time.time(),
        }))

    try:
        while True:
            msg = await ws.receive_text()
            try:
                cmd = json.loads(msg)
                action = cmd.get("action")
                key = cmd.get("key")
                if action == "start" and key:
                    pending_actions[key] = {"action": "start", "at": time.time()}
                    start_server(key)
                elif action == "stop" and key:
                    pending_actions[key] = {"action": "stop", "at": time.time()}
                    stop_server(key)
                elif action == "restart" and key:
                    pending_actions[key] = {"action": "restart", "at": time.time()}
                    stop_server(key)
                    await asyncio.sleep(0.5)
                    start_server(key)
                # Immediately push status update
                await _broadcast_status()
            except Exception:
                pass
    except WebSocketDisconnect:
        pass
    finally:
        clients.discard(ws)
        logger.info(f"Launcher client disconnected ({len(clients)} remaining)")


def main():
    port = int(os.environ.get("NETHUDS_LAUNCHER_PORT", "8400"))
    uvicorn.run(
        app,
        host=os.environ.get("NETHUDS_LAUNCHER_HOST", "0.0.0.0"),
        port=port,
        log_level="info",
    )


if __name__ == "__main__":
    main()