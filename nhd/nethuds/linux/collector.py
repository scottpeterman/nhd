"""
Linux HUD Collector — distro-aware, capability-gated telemetry.

Persistent SSH session (mirrors Arista collector pattern).
Probes host capabilities on first connect, then runs only the
collectors whose gates are satisfied.  Supports local mode
(direct /proc + /sys reads) and remote mode (SSH via Netmiko).

No root required for core data sources — runs as unprivileged user.
Optional collectors (docker, nvidia-smi, vtysh) may need group
membership or sudo NOPASSWD.
"""

import json
import logging
import re
import subprocess
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("collector")


# ═══════════════════════════════════════════════════════════
#  Collector Registry
# ═══════════════════════════════════════════════════════════
#  (data_key, method_name, gate)
#
#  gate = None          → always run
#  gate = "cap_name"    → run if self.caps[cap_name] is truthy
#  gate = "!cap_name"   → run if self.caps[cap_name] is falsy
#
#  Order matters: system/cpu/memory first (fastest, always needed),
#  heavier optional collectors later.
# ───────────────────────────────────────────────────────────

COLLECTOR_REGISTRY: list[tuple[str, str, str | None]] = [
    # ── Always-on core ──────────────────────────────────
    ("system",       "_collect_system",       None),
    ("cpu",          "_collect_cpu",          None),
    ("memory",       "_collect_memory",       None),
    ("storage",      "_collect_storage",      None),
    ("interfaces",   "_collect_interfaces",   None),
    ("routes",       "_collect_routes",       None),
    ("connections",  "_collect_connections",   None),
    ("logging",      "_collect_journal",      None),

    # ── Capability-gated ────────────────────────────────
    ("thermal",      "_collect_thermal",      "has_thermal"),
    ("lldp",         "_collect_lldp",         "has_lldpd"),
    ("services",     "_collect_services",     "has_systemd"),
    ("services_rc",  "_collect_services_rc",  "has_openrc"),
    ("docker",       "_collect_docker",       "has_docker"),
    ("podman",       "_collect_podman",       "has_podman"),
    ("nomad",        "_collect_nomad",        "has_nomad"),
    ("gpu_nvidia",   "_collect_gpu_nvidia",   "has_nvidia"),
    ("gpu_amd",      "_collect_gpu_amd",      "has_amdgpu"),
    ("frr",          "_collect_frr",          "has_frr"),
    ("bird",         "_collect_bird",         "has_bird"),
    ("proxmox",      "_collect_proxmox",      "has_proxmox"),
    ("libvirt",      "_collect_libvirt",      "has_libvirt"),
    ("zfs",          "_collect_zfs",          "has_zfs"),
    ("lvm",          "_collect_lvm",          "has_lvm"),
    ("smart",        "_collect_smart",        "has_smartctl"),
]


# ═══════════════════════════════════════════════════════════
#  Local-mode helpers (used when target is localhost)
# ═══════════════════════════════════════════════════════════

def _local_run(cmd: str, timeout: int = 5) -> str:
    """Run a shell command locally, return stdout or empty string."""
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return r.stdout if r.returncode == 0 else ""
    except Exception as e:
        logger.debug(f"Local command failed '{cmd}': {e}")
        return ""


def _local_read(path: str) -> str:
    """Read a file, return contents or empty string."""
    try:
        return Path(path).read_text()
    except Exception:
        return ""


# ═══════════════════════════════════════════════════════════
#  LinuxCollector
# ═══════════════════════════════════════════════════════════

class LinuxCollector:
    """
    Collects operational state from a Linux host.

    Session lifecycle:
        __init__  →  _ensure_connected()  →  _probe()  →  poll…poll…poll
                         ↑ reconnect if session drops ↑

    The probe runs once per connection.  Capabilities are cached
    and included in every telemetry push so the frontend can
    adapt its panel layout.
    """

    def __init__(self, device_config: dict):
        self.config = device_config
        self.hostname = device_config.get("host", "localhost")
        self.is_local = self.hostname in ("localhost", "127.0.0.1", "::1")

        # ── Netmiko params (remote mode) ─────────────
        self.device_params: dict[str, Any] = {}
        if not self.is_local:
            self.device_params = {
                "device_type": device_config.get("device_type", "linux"),
                "host": device_config["host"],
                "username": device_config.get("username"),
                "timeout": device_config.get("timeout", 30),
                "session_timeout": device_config.get("session_timeout", 120),
                "conn_timeout": device_config.get("timeout", 30),
            }
            if device_config.get("use_keys", False):
                self.device_params["use_keys"] = True
                if device_config.get("key_file"):
                    self.device_params["key_file"] = str(
                        Path(device_config["key_file"]).expanduser()
                    )
            if device_config.get("password"):
                self.device_params["password"] = device_config["password"]

            if device_config.get("legacy_ssh", False):
                self.device_params["disabled_algorithms"] = {
                    "pubkeys": ["rsa-sha2-256", "rsa-sha2-512"],
                }
                logger.info(f"Legacy SSH mode enabled for {self.hostname}")

        # ── Session state ────────────────────────────
        self._conn = None
        self._prompt_re: str | None = None
        self._probed: bool = False
        self.caps: dict[str, Any] = {}

        # ── Telemetry state ──────────────────────────
        self._last_data: dict[str, Any] | None = None
        self._last_error: str | None = None
        self._last_collect_time: float = 0
        self._collect_count: int = 0

        mode = "local" if self.is_local else "remote"
        logger.info(f"LinuxCollector initialized: {self.hostname} ({mode})")

    # ─────────────────────────────────────────────────────
    #  Session management (mirrors Arista pattern)
    # ─────────────────────────────────────────────────────

    def _ensure_connected(self):
        """Establish or re-establish a persistent SSH session."""
        if self.is_local:
            return  # no session needed

        from netmiko import ConnectHandler
        from netmiko.exceptions import (
            NetmikoTimeoutException,
            NetmikoAuthenticationException,
        )

        if self._conn is not None:
            try:
                if self._conn.is_alive():
                    return
            except Exception:
                pass
            # Session died — clean up and reconnect
            try:
                self._conn.disconnect()
            except Exception:
                pass
            self._conn = None
            self._prompt_re = None
            self._probed = False
            logger.info(f"Session to {self.hostname} dropped, reconnecting")

        self._conn = ConnectHandler(**self.device_params)
        _prompt = self._conn.find_prompt().strip()
        # Build a prompt regex that handles $ and # endings
        base = re.escape(_prompt.rstrip("$#>"))
        self._prompt_re = base + r"[$#>]\s*$"
        logger.info(f"Persistent session to {self.hostname}, prompt: '{_prompt}'")

    def _send(self, cmd: str, timeout: int = 10) -> str:
        """Send a command over the persistent SSH session."""
        if self.is_local:
            return _local_run(cmd, timeout=timeout)

        kwargs: dict[str, Any] = {
            "command_string": cmd,
            "read_timeout": timeout,
        }
        if self._prompt_re:
            kwargs["expect_string"] = self._prompt_re
        try:
            return self._conn.send_command(**kwargs)
        except Exception as e:
            logger.debug(f"Command failed '{cmd}': {e}")
            # If the socket is dead, mark connection for reconnect
            if "socket" in str(e).lower() or "closed" in str(e).lower():
                self._conn = None
                self._prompt_re = None
                self._probed = False
            return ""

    def _read(self, path: str) -> str:
        """Read a file — direct on local, cat over SSH on remote."""
        if self.is_local:
            return _local_read(path)
        return self._send(f"cat {path} 2>/dev/null", timeout=5)

    def test_connect(self):
        """Test SSH connectivity. Raises on failure."""
        self._ensure_connected()

    def disconnect(self):
        """Tear down the persistent session."""
        if self._conn:
            try:
                self._conn.disconnect()
            except Exception:
                pass
            self._conn = None
            self._prompt_re = None
            self._probed = False
            logger.info(f"Disconnected from {self.hostname}")

    # ─────────────────────────────────────────────────────
    #  Capability probe — runs ONCE per connection
    # ─────────────────────────────────────────────────────

    def _probe(self):
        """
        Fingerprint the host: distro, init system, available tooling.

        Batches all existence checks into a single compound shell command
        to minimize SSH round-trips.  Result is cached in self.caps and
        included in every telemetry push.
        """
        if self._probed:
            return
        t0 = time.time()
        logger.info(f"Probing capabilities on {self.hostname}")

        caps: dict[str, Any] = {
            # ── Identity ─────────────────────────────
            "distro_id":     "",       # e.g. "ubuntu", "rocky", "alpine"
            "distro_id_like": "",      # e.g. "debian", "rhel fedora"
            "distro_name":   "",       # PRETTY_NAME
            "distro_version": "",      # VERSION_ID
            # ── Init system ──────────────────────────
            "has_systemd":   False,
            "has_openrc":    False,
            "has_runit":     False,
            # ── Networking ───────────────────────────
            "has_lldpd":     False,
            "has_frr":       False,    # vtysh (FRRouting / Cumulus)
            "has_bird":      False,    # birdc
            "has_iproute2":  True,     # assume true, verify
            # ── Containers & VMs ─────────────────────
            "has_docker":    False,
            "has_podman":    False,
            "has_nomad":     False,
            "has_proxmox":   False,
            "has_libvirt":   False,    # virsh
            "is_container":  False,    # running inside a container
            "is_wsl":        False,
            # ── Hardware ─────────────────────────────
            "has_thermal":   False,    # /sys/class/thermal exists with zones
            "has_lm_sensors": False,
            "has_nvidia":    False,    # nvidia-smi
            "has_amdgpu":    False,    # /sys/class/drm/card*/device/gpu_busy_percent
            # ── Storage ──────────────────────────────
            "has_zfs":       False,
            "has_lvm":       False,
            "has_smartctl":  False,
        }

        # ── Phase 1: Read /etc/os-release ────────────
        os_release = self._read("/etc/os-release")
        for line in os_release.splitlines():
            if "=" not in line:
                continue
            key, val = line.split("=", 1)
            val = val.strip('"')
            if key == "ID":
                caps["distro_id"] = val
            elif key == "ID_LIKE":
                caps["distro_id_like"] = val
            elif key == "PRETTY_NAME":
                caps["distro_name"] = val
            elif key == "VERSION_ID":
                caps["distro_version"] = val

        # ── Phase 2: Batch existence checks ──────────
        # One compound command, parse the output tokens.
        # Each check echoes a known token on success.
        probe_cmd = " ; ".join([
            # Init system
            "command -v systemctl >/dev/null 2>&1 && echo CAP:has_systemd",
            "command -v rc-service >/dev/null 2>&1 && echo CAP:has_openrc",
            "command -v sv >/dev/null 2>&1 && test -d /etc/sv && echo CAP:has_runit",
            # Networking
            "command -v lldpctl >/dev/null 2>&1 && echo CAP:has_lldpd",
            "command -v vtysh >/dev/null 2>&1 && echo CAP:has_frr",
            "command -v birdc >/dev/null 2>&1 && echo CAP:has_bird",
            "command -v ip >/dev/null 2>&1 && echo CAP:has_iproute2",
            # Containers & VMs
            "command -v docker >/dev/null 2>&1 && echo CAP:has_docker",
            "command -v podman >/dev/null 2>&1 && echo CAP:has_podman",
            "command -v nomad >/dev/null 2>&1 && echo CAP:has_nomad",
            "test -f /etc/pve/local/pve-ssl.pem && echo CAP:has_proxmox",
            "command -v virsh >/dev/null 2>&1 && echo CAP:has_libvirt",
            "test -f /.dockerenv && echo CAP:is_container",
            "grep -qsm1 docker /proc/1/cgroup 2>/dev/null && echo CAP:is_container",
            "grep -qsi microsoft /proc/version 2>/dev/null && echo CAP:is_wsl",
            # Hardware
            "ls /sys/class/thermal/thermal_zone*/temp >/dev/null 2>&1 && echo CAP:has_thermal",
            "command -v sensors >/dev/null 2>&1 && echo CAP:has_lm_sensors",
            "command -v nvidia-smi >/dev/null 2>&1 && echo CAP:has_nvidia",
            "ls /sys/class/drm/card*/device/gpu_busy_percent >/dev/null 2>&1 && echo CAP:has_amdgpu",
            # Storage
            "command -v zpool >/dev/null 2>&1 && echo CAP:has_zfs",
            "command -v lvs >/dev/null 2>&1 && echo CAP:has_lvm",
            "command -v smartctl >/dev/null 2>&1 && echo CAP:has_smartctl",
        ])

        raw = self._send(probe_cmd, timeout=15)
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("CAP:"):
                cap_key = line[4:]
                if cap_key in caps:
                    caps[cap_key] = True

        # ── Phase 3: Derive distro family ────────────
        did = caps["distro_id"].lower()
        did_like = caps["distro_id_like"].lower()

        if did in ("debian", "ubuntu", "linuxmint", "pop", "kali", "raspbian") \
                or "debian" in did_like:
            caps["distro_family"] = "debian"
        elif did in ("rhel", "centos", "rocky", "alma", "fedora", "ol", "amzn") \
                or "rhel" in did_like or "fedora" in did_like:
            caps["distro_family"] = "rhel"
        elif did in ("alpine",):
            caps["distro_family"] = "alpine"
        elif did in ("arch", "manjaro", "endeavouros") or "arch" in did_like:
            caps["distro_family"] = "arch"
        elif did in ("suse", "opensuse-leap", "opensuse-tumbleweed") \
                or "suse" in did_like:
            caps["distro_family"] = "suse"
        elif did in ("cumulus",) or "cumulus" in did_like:
            caps["distro_family"] = "cumulus"
            caps["has_frr"] = True  # Cumulus always has FRR
        elif did in ("vyos",):
            caps["distro_family"] = "vyos"
        else:
            caps["distro_family"] = "unknown"

        self.caps = caps
        self._probed = True

        # Log what we found
        active = [k for k, v in caps.items()
                  if isinstance(v, bool) and v]
        elapsed = time.time() - t0
        logger.info(
            f"Probe complete in {elapsed:.1f}s: "
            f"{caps['distro_name']} ({caps['distro_family']}) — "
            f"capabilities: {', '.join(active)}"
        )

    def _gate_met(self, gate: str | None) -> bool:
        """Check if a collector's capability gate is satisfied."""
        if gate is None:
            return True
        if gate.startswith("!"):
            return not self.caps.get(gate[1:], False)
        return bool(self.caps.get(gate, False))

    # ─────────────────────────────────────────────────────
    #  Main collection loop
    # ─────────────────────────────────────────────────────

    def collect(self, on_progress=None) -> dict[str, Any]:
        """
        Connect (if needed), probe (if needed), run gated collectors.
        Returns last good data on connection failure.
        """
        t0 = time.time()
        self._collect_count += 1
        logger.info(f"Poll #{self._collect_count} starting for {self.hostname}")

        # ── Connect ──────────────────────────────────
        try:
            self._ensure_connected()
        except Exception as e:
            self._last_error = f"Connection failed: {e}"
            logger.error(self._last_error)
            return self._stale_or_error()

        # ── Probe (first time or after reconnect) ────
        try:
            self._probe()
        except Exception as e:
            logger.warning(f"Probe failed, running with empty caps: {e}")
            self._probed = True  # don't retry every poll

        # ── Build active collector list ──────────────
        active = [
            (key, method_name)
            for key, method_name, gate in COLLECTOR_REGISTRY
            if self._gate_met(gate)
        ]
        total = len(active)
        skipped = len(COLLECTOR_REGISTRY) - total

        data: dict[str, Any] = {
            "meta": {
                "hostname": self.hostname,
                "poll_count": self._collect_count,
                "poll_time": None,
                "error": None,
                "stale": False,
                "timestamp": time.time(),
                "collector_timing": {},
            },
            "caps": dict(self.caps),
        }

        # ── Run collectors ───────────────────────────
        for idx, (key, method_name) in enumerate(active):
            if on_progress:
                try:
                    on_progress(key, idx, total, time.time() - t0, "start")
                except Exception:
                    pass

            ct0 = time.time()
            try:
                method = getattr(self, method_name)
                data[key] = method()
            except Exception as e:
                logger.warning(f"Collector '{key}' failed: {e}")
                data[key] = {"_error": str(e)}
                # Session-fatal errors
                if "socket" in str(e).lower() or "closed" in str(e).lower():
                    self._conn = None
                    self._prompt_re = None
                    self._probed = False
                    logger.error("Session lost mid-collection, aborting poll")
                    break

            data["meta"]["collector_timing"][key] = round(time.time() - ct0, 3)

            if on_progress:
                try:
                    on_progress(key, idx + 1, total, time.time() - t0, "done")
                except Exception:
                    pass

        elapsed = time.time() - t0
        data["meta"]["poll_time"] = round(elapsed, 2)
        data["meta"]["collectors_run"] = len(active)
        data["meta"]["collectors_skipped"] = skipped
        self._last_data = data
        self._last_error = None
        self._last_collect_time = time.time()

        logger.info(
            f"Poll #{self._collect_count} complete in {elapsed:.1f}s "
            f"({len(active)} collectors, {skipped} skipped)"
        )
        return data

    def _stale_or_error(self) -> dict[str, Any]:
        """Return last good data with error flag, or error-only dict."""
        if self._last_data:
            stale = dict(self._last_data)
            stale["meta"] = dict(stale.get("meta", {}))
            stale["meta"]["error"] = self._last_error
            stale["meta"]["stale"] = True
            stale["meta"]["timestamp"] = time.time()
            return stale

        return {
            "meta": {
                "hostname": self.hostname,
                "poll_count": self._collect_count,
                "poll_time": 0,
                "error": self._last_error,
                "stale": False,
                "timestamp": time.time(),
            },
            "caps": dict(self.caps),
        }

    # ═════════════════════════════════════════════════════
    #  CORE COLLECTORS (always-on)
    # ═════════════════════════════════════════════════════

    def _collect_system(self) -> dict[str, Any]:
        """System identity: hostname, kernel, distro, uptime."""
        result = {
            "hostname": "---",
            "kernel": "---",
            "distro": self.caps.get("distro_name", "---"),
            "arch": "---",
            "uptime_seconds": 0,
            "uptime_human": "---",
        }

        result["hostname"] = self._read("/etc/hostname").strip() or self.hostname
        result["kernel"] = self._send("uname -r").strip() or "---"
        result["arch"] = self._send("uname -m").strip() or "---"

        raw = self._read("/proc/uptime").split()
        if raw:
            secs = int(float(raw[0]))
            result["uptime_seconds"] = secs
            days, rem = divmod(secs, 86400)
            hours, rem = divmod(rem, 3600)
            mins, _ = divmod(rem, 60)
            parts = []
            if days:
                parts.append(f"{days}d")
            if hours:
                parts.append(f"{hours}h")
            parts.append(f"{mins}m")
            result["uptime_human"] = " ".join(parts)

        return result

    def _collect_cpu(self) -> dict[str, Any]:
        """CPU load, count, and top processes."""
        result: dict[str, Any] = {
            "load_1": 0.0, "load_5": 0.0, "load_15": 0.0,
            "cpu_count": 1, "cpu_pct": 0.0, "top_processes": [],
        }

        raw = self._read("/proc/loadavg").split()
        if len(raw) >= 3:
            result["load_1"] = float(raw[0])
            result["load_5"] = float(raw[1])
            result["load_15"] = float(raw[2])

        ncpu = self._send("nproc").strip()
        result["cpu_count"] = int(ncpu) if ncpu.isdigit() else 1

        result["cpu_pct"] = min(
            100.0,
            round((result["load_1"] / result["cpu_count"]) * 100, 1),
        )

        raw = self._send("ps aux --sort=-%cpu --no-headers 2>/dev/null | head -10")
        for line in raw.splitlines()[:10]:
            parts = line.split(None, 10)
            if len(parts) >= 11:
                result["top_processes"].append({
                    "user": parts[0],
                    "pid": int(parts[1]) if parts[1].isdigit() else 0,
                    "cpu": float(parts[2]) if _is_float(parts[2]) else 0.0,
                    "mem": float(parts[3]) if _is_float(parts[3]) else 0.0,
                    "command": parts[10][:80],
                })

        return result

    def _collect_memory(self) -> dict[str, Any]:
        """Memory and swap from /proc/meminfo."""
        info: dict[str, int] = {}
        for line in self._read("/proc/meminfo").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                info[parts[0].rstrip(":")] = int(parts[1])

        total = info.get("MemTotal", 0)
        avail = info.get("MemAvailable", 0)
        swap_total = info.get("SwapTotal", 0)
        swap_free = info.get("SwapFree", 0)

        return {
            "total_kb": total,
            "available_kb": avail,
            "used_kb": total - avail,
            "buffers_kb": info.get("Buffers", 0),
            "cached_kb": info.get("Cached", 0),
            "mem_pct": round(((total - avail) / total * 100), 1) if total else 0,
            "swap_total_kb": swap_total,
            "swap_used_kb": swap_total - swap_free,
            "swap_pct": (
                round(((swap_total - swap_free) / swap_total * 100), 1)
                if swap_total else 0
            ),
        }

    def _collect_storage(self) -> list[dict[str, Any]]:
        """Filesystem usage from df."""
        mounts = []
        raw = self._send(
            "df -h -x tmpfs -x devtmpfs -x squashfs -x overlay "
            "--output=target,fstype,size,used,avail,pcent 2>/dev/null"
        )
        for line in raw.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 6:
                pct_str = parts[5].rstrip("%")
                mounts.append({
                    "mount": parts[0],
                    "fstype": parts[1],
                    "size": parts[2],
                    "used": parts[3],
                    "avail": parts[4],
                    "pct": int(pct_str) if pct_str.isdigit() else 0,
                })
        return mounts

    def _collect_interfaces(self) -> list[dict[str, Any]]:
        """Network interfaces via ip -j (iproute2 JSON)."""
        interfaces = []

        raw = self._send("ip -j link show 2>/dev/null")
        if not raw:
            return interfaces
        try:
            links = json.loads(raw)
        except json.JSONDecodeError:
            return interfaces

        # Build address map
        addr_map: dict[str, list[str]] = {}
        raw_addr = self._send("ip -j addr show 2>/dev/null")
        if raw_addr:
            try:
                for a in json.loads(raw_addr):
                    name = a.get("ifname", "")
                    ips = [
                        f"{ai['local']}/{ai.get('prefixlen', '')}"
                        for ai in a.get("addr_info", [])
                        if ai.get("local")
                    ]
                    if ips:
                        addr_map[name] = ips
            except json.JSONDecodeError:
                pass

        for link in links:
            name = link.get("ifname", "")
            if name == "lo":
                continue
            operstate = link.get("operstate", "UNKNOWN")

            speed = self._read(f"/sys/class/net/{name}/speed").strip()
            speed = f"{speed}Mbps" if speed and speed != "-1" else ""

            tx = self._read(f"/sys/class/net/{name}/statistics/tx_bytes").strip()
            rx = self._read(f"/sys/class/net/{name}/statistics/rx_bytes").strip()

            interfaces.append({
                "name": name,
                "operstate": operstate,
                "mtu": link.get("mtu", 0),
                "mac": link.get("address", ""),
                "speed": speed,
                "kind": link.get("link_type", ""),
                "flags": link.get("flags", []),
                "addresses": addr_map.get(name, []),
                "tx_bytes": int(tx) if tx.isdigit() else 0,
                "rx_bytes": int(rx) if rx.isdigit() else 0,
            })

        return interfaces

    def _collect_routes(self) -> dict[str, Any]:
        """Routing table summary from ip route."""
        result: dict[str, Any] = {
            "total": 0,
            "default_gw": "---",
            "protocols": {},
        }

        raw = self._send("ip route show default 2>/dev/null")
        m = re.search(r"default via (\S+)", raw)
        if m:
            result["default_gw"] = m.group(1)

        raw = self._send("ip route show table all 2>/dev/null")
        lines = [l for l in raw.splitlines() if l.strip()]
        result["total"] = len(lines)

        proto_count: dict[str, int] = {}
        for line in lines:
            m2 = re.search(r"proto (\S+)", line)
            proto = m2.group(1) if m2 else "local"
            proto_count[proto] = proto_count.get(proto, 0) + 1
        result["protocols"] = proto_count

        return result

    def _collect_connections(self) -> dict[str, Any]:
        """Active connections from ss."""
        result: dict[str, Any] = {
            "tcp_established": 0,
            "tcp_listen": 0,
            "udp": 0,
            "listeners": [],
        }

        raw = self._send("ss -tunas 2>/dev/null")
        for line in raw.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                if parts[0] == "ESTAB":
                    result["tcp_established"] += 1
                elif parts[0] == "LISTEN":
                    result["tcp_listen"] += 1
                elif parts[0] == "UNCONN":
                    result["udp"] += 1

        raw2 = self._send("ss -tlnp 2>/dev/null")
        for line in raw2.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4:
                listen_addr = parts[3]
                process = parts[5] if len(parts) > 5 else ""
                m = re.search(r'"(\w+)"', process)
                result["listeners"].append({
                    "address": listen_addr,
                    "process": m.group(1) if m else "---",
                })

        return result

    def _collect_journal(self) -> list[dict[str, Any]]:
        """Recent log entries — journalctl JSON → text → syslog fallback."""
        entries: list[dict[str, Any]] = []

        # Try journalctl JSON first
        raw = self._send(
            "journalctl -n 40 --no-pager -o json 2>/dev/null",
            timeout=10,
        )
        if raw and raw.strip().startswith("{"):
            for line in raw.splitlines():
                try:
                    j = json.loads(line)
                    ts_usec = j.get("__REALTIME_TIMESTAMP", "")
                    ts_human = ""
                    if ts_usec:
                        try:
                            ts_human = time.strftime(
                                "%b %d %H:%M:%S",
                                time.localtime(int(ts_usec) / 1e6),
                            )
                        except (ValueError, OSError):
                            ts_human = ts_usec
                    entries.append({
                        "timestamp": ts_human,
                        "source": j.get(
                            "SYSLOG_IDENTIFIER", j.get("_COMM", "unknown")
                        ),
                        "priority": int(j.get("PRIORITY", 6)),
                        "message": j.get("MESSAGE", ""),
                        "unit": j.get("_SYSTEMD_UNIT", ""),
                    })
                except json.JSONDecodeError:
                    continue
            if entries:
                return entries

        # Fallback: journalctl short → syslog → messages
        raw2 = self._send(
            "journalctl -n 40 --no-pager 2>/dev/null "
            "|| tail -40 /var/log/syslog 2>/dev/null "
            "|| tail -40 /var/log/messages 2>/dev/null",
            timeout=10,
        )
        pat = re.compile(
            r"^(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s+(.+)$",
            re.MULTILINE,
        )
        for m in pat.finditer(raw2):
            entries.append({
                "timestamp": m.group(1),
                "host": m.group(2),
                "source": m.group(3),
                "priority": 6,
                "message": m.group(4).strip(),
                "unit": "",
            })

        return entries

    # ═════════════════════════════════════════════════════
    #  GATED COLLECTORS (run only when capability detected)
    # ═════════════════════════════════════════════════════

    # ── Thermal ──────────────────────────────────────────

    def _collect_thermal(self) -> list[dict[str, Any]]:
        """Temperature sensors from /sys/class/thermal + lm-sensors."""
        sensors = []

        # /sys/class/thermal zones
        raw = self._send(
            "for z in /sys/class/thermal/thermal_zone*; do "
            "echo \"$(cat $z/type 2>/dev/null)|$(cat $z/temp 2>/dev/null)\"; "
            "done 2>/dev/null"
        )
        for line in raw.splitlines():
            parts = line.strip().split("|")
            if len(parts) == 2 and parts[1].isdigit():
                sensors.append({
                    "name": parts[0] or "zone",
                    "temp": round(int(parts[1]) / 1000.0, 1),
                    "source": "sys",
                })

        # lm-sensors overlay (if available)
        if self.caps.get("has_lm_sensors"):
            raw = self._send("sensors -j 2>/dev/null")
            if raw and raw.strip().startswith("{"):
                try:
                    data = json.loads(raw)
                    for chip, readings in data.items():
                        if not isinstance(readings, dict):
                            continue
                        for label, values in readings.items():
                            if not isinstance(values, dict):
                                continue
                            for k, v in values.items():
                                if (
                                    k.startswith("temp")
                                    and k.endswith("_input")
                                    and isinstance(v, (int, float))
                                ):
                                    sensors.append({
                                        "name": f"{chip}:{label}",
                                        "temp": round(v, 1),
                                        "source": "lm-sensors",
                                    })
                except json.JSONDecodeError:
                    pass

        return sensors

    # ── LLDP ─────────────────────────────────────────────

    def _collect_lldp(self) -> list[dict[str, Any]]:
        """LLDP neighbors from lldpctl."""
        raw = self._send("lldpctl -f json 2>/dev/null")
        if not raw or not raw.strip().startswith("{"):
            return []
        try:
            data = json.loads(raw)
            neighbors = []
            lldp = data.get("lldp", {}).get("interface", {})
            if isinstance(lldp, dict):
                for local_intf, info in lldp.items():
                    chassis = info.get("chassis", {})
                    port = info.get("port", {})
                    for cname, cdata in chassis.items():
                        neighbors.append({
                            "local_intf": local_intf,
                            "device": cname,
                            "remote_port": port.get("id", {}).get("value", ""),
                            "description": cdata.get("descr", ""),
                        })
            elif isinstance(lldp, list):
                # Some lldpctl versions return a list
                for entry in lldp:
                    if isinstance(entry, dict):
                        local_intf = entry.get("name", "")
                        chassis = entry.get("chassis", {})
                        port = entry.get("port", {})
                        for cname, cdata in chassis.items():
                            neighbors.append({
                                "local_intf": local_intf,
                                "device": cname,
                                "remote_port": port.get("id", {}).get("value", ""),
                                "description": cdata.get("descr", ""),
                            })
            return neighbors
        except (json.JSONDecodeError, AttributeError):
            return []

    # ── Services: systemd ────────────────────────────────

    def _collect_services(self) -> dict[str, Any]:
        """Systemd service inventory."""
        result: dict[str, Any] = {
            "init": "systemd",
            "services": [],
            "failed_count": 0,
            "active_count": 0,
            "total": 0,
        }

        raw = self._send(
            "systemctl list-units --type=service --all "
            "--no-pager --plain --no-legend 2>/dev/null"
        )
        for line in raw.splitlines():
            parts = line.split(None, 4)
            if len(parts) >= 4:
                svc = {
                    "unit": parts[0],
                    "load": parts[1],
                    "active": parts[2],
                    "sub": parts[3],
                    "description": parts[4] if len(parts) > 4 else "",
                }
                result["services"].append(svc)
                result["total"] += 1
                if svc["active"] == "active":
                    result["active_count"] += 1
                if svc["active"] == "failed":
                    result["failed_count"] += 1

        return result

    # ── Services: OpenRC (Alpine, Gentoo) ────────────────

    def _collect_services_rc(self) -> dict[str, Any]:
        """OpenRC service inventory."""
        result: dict[str, Any] = {
            "init": "openrc",
            "services": [],
            "failed_count": 0,
            "active_count": 0,
            "total": 0,
        }

        raw = self._send("rc-status --all 2>/dev/null")
        current_runlevel = ""
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("Runlevel:") or not line.startswith(" "):
                current_runlevel = line.rstrip(":")
                continue
            # Lines like: "  sshd       [ started ]"
            m = re.match(r"(\S+)\s+\[\s*(\w+)\s*\]", line)
            if m:
                svc_name = m.group(1)
                status = m.group(2)
                result["services"].append({
                    "unit": svc_name,
                    "active": status,
                    "runlevel": current_runlevel,
                })
                result["total"] += 1
                if status == "started":
                    result["active_count"] += 1
                elif status in ("crashed", "stopped"):
                    result["failed_count"] += 1

        return result

    # ── Docker ───────────────────────────────────────────

    def _collect_docker(self) -> dict[str, Any]:
        """Docker container inventory and resource usage."""
        result: dict[str, Any] = {
            "containers": [],
            "running": 0,
            "stopped": 0,
            "total": 0,
            "images": 0,
        }

        # Container list with status
        raw = self._send(
            'docker ps -a --format '
            '"{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.State}}|{{.Ports}}" '
            '2>/dev/null'
        )
        for line in raw.splitlines():
            parts = line.strip().split("|")
            if len(parts) >= 5:
                state = parts[4].lower()
                result["containers"].append({
                    "id": parts[0][:12],
                    "name": parts[1],
                    "image": parts[2],
                    "status": parts[3],
                    "state": state,
                    "ports": parts[5] if len(parts) > 5 else "",
                })
                result["total"] += 1
                if state == "running":
                    result["running"] += 1
                else:
                    result["stopped"] += 1

        # Live stats for running containers (one-shot)
        if result["running"] > 0:
            raw_stats = self._send(
                "docker stats --no-stream --format "
                '"{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}|'
                '{{.NetIO}}|{{.BlockIO}}" 2>/dev/null',
                timeout=15,
            )
            stats_map: dict[str, dict] = {}
            for line in raw_stats.splitlines():
                parts = line.strip().split("|")
                if len(parts) >= 4:
                    stats_map[parts[0]] = {
                        "cpu_pct": parts[1].rstrip("%"),
                        "mem_usage": parts[2],
                        "mem_pct": parts[3].rstrip("%"),
                        "net_io": parts[4] if len(parts) > 4 else "",
                        "block_io": parts[5] if len(parts) > 5 else "",
                    }
            # Merge stats into container records
            for c in result["containers"]:
                if c["name"] in stats_map:
                    c["stats"] = stats_map[c["name"]]

        # Image count
        raw_img = self._send("docker images -q 2>/dev/null | wc -l")
        img_count = raw_img.strip()
        result["images"] = int(img_count) if img_count.isdigit() else 0

        return result

    # ── Podman ───────────────────────────────────────────

    def _collect_podman(self) -> dict[str, Any]:
        """Podman container inventory."""
        result: dict[str, Any] = {
            "containers": [],
            "running": 0,
            "stopped": 0,
            "total": 0,
        }

        raw = self._send(
            'podman ps -a --format '
            '"{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.State}}" '
            '2>/dev/null'
        )
        for line in raw.splitlines():
            parts = line.strip().split("|")
            if len(parts) >= 5:
                state = parts[4].lower()
                result["containers"].append({
                    "id": parts[0][:12],
                    "name": parts[1],
                    "image": parts[2],
                    "status": parts[3],
                    "state": state,
                })
                result["total"] += 1
                if state == "running":
                    result["running"] += 1
                else:
                    result["stopped"] += 1

        return result

    # ── Nomad ────────────────────────────────────────────

    def _collect_nomad(self) -> dict[str, Any]:
        """HashiCorp Nomad job/allocation state via local HTTP API."""
        result: dict[str, Any] = {
            "agent": {},
            "jobs": [],
            "allocations": [],
            "running_allocs": 0,
            "failed_allocs": 0,
            "total_jobs": 0,
        }

        # Agent self — node info, version, datacenter
        raw = self._send(
            "curl -sf http://127.0.0.1:4646/v1/agent/self 2>/dev/null",
            timeout=5,
        )
        if raw and raw.strip().startswith("{"):
            try:
                agent = json.loads(raw)
                member = agent.get("member", {})
                cfg = agent.get("config", {})
                stats = agent.get("stats", {})
                result["agent"] = {
                    "name": member.get("Name", ""),
                    "version": cfg.get("Version", member.get("Tags", {}).get("build", "")),
                    "datacenter": cfg.get("Datacenter", member.get("Tags", {}).get("dc", "")),
                    "region": cfg.get("Region", ""),
                    "node_id": cfg.get("NodeID", "")[:8] if cfg.get("NodeID") else "",
                    "uptime": stats.get("client", {}).get("uptime", ""),
                }
            except json.JSONDecodeError:
                pass

        # Jobs list
        raw = self._send(
            "curl -sf http://127.0.0.1:4646/v1/jobs 2>/dev/null",
            timeout=10,
        )
        if raw and raw.strip().startswith("["):
            try:
                jobs = json.loads(raw)
                for j in jobs:
                    result["jobs"].append({
                        "id": j.get("ID", ""),
                        "name": j.get("Name", ""),
                        "type": j.get("Type", ""),
                        "status": j.get("Status", ""),
                        "priority": j.get("Priority", 50),
                        "datacenters": j.get("Datacenters", []),
                        "task_groups": j.get("JobSummary", {}).get("Summary", {}),
                    })
                result["total_jobs"] = len(jobs)
            except json.JSONDecodeError:
                pass

        # Allocations — lightweight query (no task states)
        raw = self._send(
            "curl -sf 'http://127.0.0.1:4646/v1/allocations?task_states=false&resources=false' 2>/dev/null",
            timeout=10,
        )
        if raw and raw.strip().startswith("["):
            try:
                allocs = json.loads(raw)
                for a in allocs:
                    status = a.get("ClientStatus", "")
                    alloc = {
                        "id": a.get("ID", "")[:8],
                        "job": a.get("JobID", ""),
                        "task_group": a.get("TaskGroup", ""),
                        "status": status,
                        "desired": a.get("DesiredStatus", ""),
                        "node": a.get("NodeID", "")[:8],
                        "created": a.get("CreateTime", 0),
                    }
                    result["allocations"].append(alloc)
                    if status == "running":
                        result["running_allocs"] += 1
                    elif status == "failed":
                        result["failed_allocs"] += 1
            except json.JSONDecodeError:
                pass

        return result

    # ── NVIDIA GPU ───────────────────────────────────────

    def _collect_gpu_nvidia(self) -> dict[str, Any]:
        """NVIDIA GPU telemetry via nvidia-smi."""
        result: dict[str, Any] = {"gpus": []}

        raw = self._send(
            "nvidia-smi --query-gpu="
            "index,name,temperature.gpu,utilization.gpu,utilization.memory,"
            "memory.used,memory.total,power.draw,power.limit,fan.speed,"
            "pstate,clocks.gr,clocks.mem "
            "--format=csv,noheader,nounits 2>/dev/null"
        )
        for line in raw.splitlines():
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 7:
                gpu: dict[str, Any] = {
                    "index": _safe_int(parts[0]),
                    "name": parts[1],
                    "temp_c": _safe_int(parts[2]),
                    "gpu_util_pct": _safe_int(parts[3]),
                    "mem_util_pct": _safe_int(parts[4]),
                    "mem_used_mb": _safe_int(parts[5]),
                    "mem_total_mb": _safe_int(parts[6]),
                }
                if len(parts) > 7:
                    gpu["power_draw_w"] = _safe_float(parts[7])
                if len(parts) > 8:
                    gpu["power_limit_w"] = _safe_float(parts[8])
                if len(parts) > 9:
                    gpu["fan_pct"] = _safe_int(parts[9])
                if len(parts) > 10:
                    gpu["pstate"] = parts[10]
                if len(parts) > 11:
                    gpu["clock_core_mhz"] = _safe_int(parts[11])
                if len(parts) > 12:
                    gpu["clock_mem_mhz"] = _safe_int(parts[12])
                result["gpus"].append(gpu)

        # Running GPU processes
        raw_proc = self._send(
            "nvidia-smi --query-compute-apps="
            "pid,name,used_gpu_memory "
            "--format=csv,noheader,nounits 2>/dev/null"
        )
        procs = []
        for line in raw_proc.splitlines():
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 3:
                procs.append({
                    "pid": _safe_int(parts[0]),
                    "name": parts[1],
                    "mem_mb": _safe_int(parts[2]),
                })
        result["processes"] = procs

        return result

    # ── AMD GPU ──────────────────────────────────────────

    def _collect_gpu_amd(self) -> dict[str, Any]:
        """AMD GPU telemetry from sysfs."""
        result: dict[str, Any] = {"gpus": []}

        # Find GPU cards
        raw = self._send(
            "for d in /sys/class/drm/card[0-9]*/device; do "
            "echo \"$(basename $(dirname $d))|"
            "$(cat $d/gpu_busy_percent 2>/dev/null)|"
            "$(cat $d/hwmon/hwmon*/temp1_input 2>/dev/null)|"
            "$(cat $d/mem_info_vram_used 2>/dev/null)|"
            "$(cat $d/mem_info_vram_total 2>/dev/null)\"; "
            "done 2>/dev/null"
        )
        for line in raw.splitlines():
            parts = line.strip().split("|")
            if len(parts) >= 3:
                gpu: dict[str, Any] = {
                    "card": parts[0],
                    "gpu_util_pct": _safe_int(parts[1]),
                    "temp_c": round(_safe_int(parts[2]) / 1000.0, 1) if parts[2].isdigit() else 0,
                }
                if len(parts) > 3 and parts[3].isdigit():
                    gpu["mem_used_mb"] = _safe_int(parts[3]) // (1024 * 1024)
                if len(parts) > 4 and parts[4].isdigit():
                    gpu["mem_total_mb"] = _safe_int(parts[4]) // (1024 * 1024)
                result["gpus"].append(gpu)

        return result

    # ── FRRouting ────────────────────────────────────────

    def _collect_frr(self) -> dict[str, Any]:
        """FRRouting state via vtysh — BGP, OSPF, route summary."""
        result: dict[str, Any] = {
            "bgp_summary": None,
            "ospf_neighbors": None,
            "route_summary": None,
            "version": "",
        }

        # FRR version
        raw = self._send("vtysh -c 'show version' 2>/dev/null")
        for line in raw.splitlines()[:3]:
            if "frrouting" in line.lower() or "frr" in line.lower():
                result["version"] = line.strip()
                break

        # BGP summary (JSON where supported)
        raw = self._send("vtysh -c 'show bgp summary json' 2>/dev/null", timeout=15)
        if raw and raw.strip().startswith("{"):
            try:
                result["bgp_summary"] = json.loads(raw)
            except json.JSONDecodeError:
                pass

        # If JSON BGP failed, try text
        if result["bgp_summary"] is None:
            raw = self._send("vtysh -c 'show ip bgp summary' 2>/dev/null", timeout=15)
            if raw.strip():
                result["bgp_summary"] = {"_raw": raw.strip()}

        # OSPF neighbors (JSON)
        raw = self._send(
            "vtysh -c 'show ip ospf neighbor json' 2>/dev/null", timeout=10
        )
        if raw and raw.strip().startswith("{"):
            try:
                result["ospf_neighbors"] = json.loads(raw)
            except json.JSONDecodeError:
                pass

        # Route summary
        raw = self._send(
            "vtysh -c 'show ip route summary json' 2>/dev/null", timeout=10
        )
        if raw and raw.strip().startswith("{"):
            try:
                result["route_summary"] = json.loads(raw)
            except json.JSONDecodeError:
                pass
        elif not result["route_summary"]:
            raw = self._send(
                "vtysh -c 'show ip route summary' 2>/dev/null", timeout=10
            )
            if raw.strip():
                result["route_summary"] = {"_raw": raw.strip()}

        return result

    # ── BIRD ─────────────────────────────────────────────

    def _collect_bird(self) -> dict[str, Any]:
        """BIRD routing daemon state via birdc."""
        result: dict[str, Any] = {
            "protocols": [],
            "route_count": 0,
        }

        raw = self._send("birdc show protocols all 2>/dev/null", timeout=10)
        if not raw:
            raw = self._send("birdc6 show protocols all 2>/dev/null", timeout=10)

        # Parse protocol summary lines
        proto_re = re.compile(
            r"^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s*(.*)",
        )
        for line in raw.splitlines():
            m = proto_re.match(line.strip())
            if m:
                result["protocols"].append({
                    "name": m.group(1),
                    "proto": m.group(2),
                    "table": m.group(3),
                    "state": m.group(4),
                    "since": m.group(5),
                    "info": m.group(6).strip(),
                })

        # Route count
        raw_count = self._send("birdc show route count 2>/dev/null")
        m = re.search(r"(\d+)\s+of\s+(\d+)\s+routes", raw_count)
        if m:
            result["route_count"] = int(m.group(2))

        return result

    # ── Proxmox ──────────────────────────────────────────

    def _collect_proxmox(self) -> dict[str, Any]:
        """Proxmox VM/CT inventory via pvesh."""
        result: dict[str, Any] = {
            "qemu": [],
            "lxc": [],
            "node_status": None,
        }

        # QEMU VMs
        raw = self._send(
            "pvesh get /nodes/localhost/qemu --output-format json 2>/dev/null",
            timeout=15,
        )
        if raw and raw.strip().startswith("["):
            try:
                vms = json.loads(raw)
                for vm in vms:
                    result["qemu"].append({
                        "vmid": vm.get("vmid"),
                        "name": vm.get("name", ""),
                        "status": vm.get("status", ""),
                        "cpus": vm.get("cpus", 0),
                        "mem_used": vm.get("mem", 0),
                        "mem_max": vm.get("maxmem", 0),
                        "uptime": vm.get("uptime", 0),
                    })
            except json.JSONDecodeError:
                pass

        # LXC containers
        raw = self._send(
            "pvesh get /nodes/localhost/lxc --output-format json 2>/dev/null",
            timeout=15,
        )
        if raw and raw.strip().startswith("["):
            try:
                cts = json.loads(raw)
                for ct in cts:
                    result["lxc"].append({
                        "vmid": ct.get("vmid"),
                        "name": ct.get("name", ""),
                        "status": ct.get("status", ""),
                        "cpus": ct.get("cpus", 0),
                        "mem_used": ct.get("mem", 0),
                        "mem_max": ct.get("maxmem", 0),
                    })
            except json.JSONDecodeError:
                pass

        # Node status
        raw = self._send(
            "pvesh get /nodes/localhost/status --output-format json 2>/dev/null",
            timeout=10,
        )
        if raw and raw.strip().startswith("{"):
            try:
                result["node_status"] = json.loads(raw)
            except json.JSONDecodeError:
                pass

        return result

    # ── Libvirt / KVM ────────────────────────────────────

    def _collect_libvirt(self) -> dict[str, Any]:
        """KVM/QEMU VMs via virsh."""
        result: dict[str, Any] = {"domains": []}

        raw = self._send("virsh list --all --title 2>/dev/null")
        for line in raw.splitlines()[2:]:  # skip header lines
            parts = line.split(None, 3)
            if len(parts) >= 3 and parts[0].isdigit() or parts[0] == "-":
                result["domains"].append({
                    "id": parts[0] if parts[0] != "-" else None,
                    "name": parts[1],
                    "state": parts[2],
                    "title": parts[3].strip() if len(parts) > 3 else "",
                })

        return result

    # ── ZFS ──────────────────────────────────────────────

    def _collect_zfs(self) -> dict[str, Any]:
        """ZFS pool status and dataset usage."""
        result: dict[str, Any] = {"pools": [], "datasets": []}

        # Pool status
        raw = self._send("zpool list -Hp 2>/dev/null")
        for line in raw.splitlines():
            parts = line.split("\t")
            if len(parts) >= 8:
                result["pools"].append({
                    "name": parts[0],
                    "size": int(parts[1]) if parts[1].isdigit() else 0,
                    "alloc": int(parts[2]) if parts[2].isdigit() else 0,
                    "free": int(parts[3]) if parts[3].isdigit() else 0,
                    "frag": parts[5].rstrip("%"),
                    "cap": parts[6].rstrip("%"),
                    "health": parts[7] if len(parts) > 7 else "",
                })

        # Pool health detail
        raw_health = self._send("zpool status -x 2>/dev/null")
        result["health_summary"] = raw_health.strip() if raw_health else ""

        return result

    # ── LVM ──────────────────────────────────────────────

    def _collect_lvm(self) -> dict[str, Any]:
        """Logical Volume Manager state."""
        result: dict[str, Any] = {"vgs": [], "lvs": []}

        # Volume groups
        raw = self._send(
            "vgs --noheadings --nosuffix --units g "
            "-o vg_name,vg_size,vg_free,pv_count,lv_count 2>/dev/null"
        )
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                result["vgs"].append({
                    "name": parts[0],
                    "size": parts[1],
                    "free": parts[2],
                    "pvs": parts[3] if len(parts) > 3 else "0",
                    "lvs": parts[4] if len(parts) > 4 else "0",
                })

        # Logical volumes
        raw = self._send(
            "lvs --noheadings --nosuffix --units g "
            "-o lv_name,vg_name,lv_size,lv_attr 2>/dev/null"
        )
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                result["lvs"].append({
                    "name": parts[0],
                    "vg": parts[1],
                    "size": parts[2],
                    "attr": parts[3] if len(parts) > 3 else "",
                })

        return result

    # ── SMART ────────────────────────────────────────────

    def _collect_smart(self) -> list[dict[str, Any]]:
        """S.M.A.R.T. disk health summary."""
        disks: list[dict[str, Any]] = []

        # Find block devices
        raw = self._send("lsblk -dnpo NAME,TYPE 2>/dev/null")
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "disk":
                dev = parts[0]
                # Quick health check (needs sudo or smartctl group)
                raw_smart = self._send(
                    f"smartctl -H -A {dev} --json 2>/dev/null", timeout=10
                )
                if raw_smart and raw_smart.strip().startswith("{"):
                    try:
                        sdata = json.loads(raw_smart)
                        health = sdata.get("smart_status", {})
                        disks.append({
                            "device": dev,
                            "passed": health.get("passed", None),
                            "temperature": sdata.get("temperature", {}).get(
                                "current", None
                            ),
                            "power_on_hours": _extract_smart_attr(
                                sdata, "Power_On_Hours"
                            ),
                        })
                    except json.JSONDecodeError:
                        pass

        return disks


# ═══════════════════════════════════════════════════════════
#  Utility helpers
# ═══════════════════════════════════════════════════════════

def _is_float(s: str) -> bool:
    try:
        float(s)
        return True
    except (ValueError, TypeError):
        return False


def _safe_int(s: str) -> int:
    """Parse an integer, returning 0 on failure."""
    s = s.strip()
    try:
        return int(s)
    except (ValueError, TypeError):
        return 0


def _safe_float(s: str) -> float:
    """Parse a float, returning 0.0 on failure."""
    s = s.strip()
    try:
        return float(s)
    except (ValueError, TypeError):
        return 0.0


def _extract_smart_attr(sdata: dict, attr_name: str) -> Any:
    """Extract a SMART attribute value by name from smartctl JSON."""
    for attr in sdata.get("ata_smart_attributes", {}).get("table", []):
        if attr.get("name") == attr_name:
            return attr.get("raw", {}).get("value")
    return None