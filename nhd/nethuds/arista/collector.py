"""
Arista EOS data collector using Netmiko.
Connects via SSH (key-based auth), runs show commands,
returns structured device state as a single dict.
"""

import json
import logging
import re
import time
from pathlib import Path
from typing import Any

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

from .parsers import parse_environment, parse_logging

logger = logging.getLogger("collector")


# Commands that return JSON
JSON_COMMANDS = {
    "version":     "show version | json",
    "bgp":         "show ip bgp summary | json",
    "ospf":        "show ip ospf neighbor | json",
    "lldp":        "show lldp neighbors | json",
    "routes":      "show ip route summary | json",
    "interfaces":  "show interfaces status | json",
    "proc":        "show processes top once | json",
    "counters":    "show interfaces counters | json",
    "inventory":   "show inventory | json",
}

# Commands that require text parsing
TEXT_COMMANDS = {
    "environment": "show system environment all",
}

# Logging: text-only, no | json support on most EOS versions
LOGGING_CMDS = [
    "show logging last 50",
    "show logging",          # fallback if 'last N' not supported
]


class AristaCollector:
    """Collects operational state from an Arista EOS device via Netmiko."""

    def __init__(self, device_config: dict):
        self.device_params = {
            "device_type": device_config.get("device_type", "arista_eos"),
            "host": device_config["host"],
            "username": device_config["username"],
            "use_keys": device_config.get("use_keys", True),
            "timeout": device_config.get("timeout", 45),
            "session_timeout": device_config.get("session_timeout", 60),
            "conn_timeout": device_config.get("timeout", 45),
        }
        if device_config.get("key_file"):
            self.device_params["key_file"] = str(
                Path(device_config["key_file"]).expanduser()
            )
        if device_config.get("password"):
            self.device_params["password"] = device_config["password"]
            self.device_params["use_keys"] = False

        # Legacy SSH support for older EOS/OpenSSH versions (< 7.2)
        # OpenSSH 6.6.1 doesn't support rsa-sha2-256/512 pubkey auth.
        # Disabling these forces paramiko to fall back to ssh-rsa (SHA-1).
        if device_config.get("legacy_ssh", False):
            self.device_params["disabled_algorithms"] = {
                "pubkeys": ["rsa-sha2-256", "rsa-sha2-512"],
            }
            logger.info(f"Legacy SSH mode enabled for {device_config['host']}")

        self.hostname = device_config["host"]
        self._conn = None            # persistent Netmiko connection
        self._prompt_re = None       # compiled prompt pattern
        self._last_data: dict[str, Any] | None = None
        self._last_error: str | None = None
        self._last_collect_time: float = 0
        self._collect_count: int = 0

    def _ensure_connected(self):
        """Establish or re-establish a persistent SSH session."""
        if self._conn is not None:
            try:
                if self._conn.is_alive():
                    return
            except Exception:
                pass
            try:
                self._conn.disconnect()
            except Exception:
                pass
            self._conn = None
            self._prompt_re = None
            logger.info(f"Session to {self.hostname} dropped, reconnecting")

        self._conn = ConnectHandler(**self.device_params)
        _prompt = self._conn.find_prompt().strip()
        self._prompt_re = re.escape(_prompt.rstrip(">#")) + "[>#]\\s*$"
        logger.info(f"Persistent session to {self.hostname}, prompt: '{_prompt}'")

        # Disable pagination at the terminal level
        try:
            self._conn.send_command(
                "terminal length 0",
                expect_string=self._prompt_re, read_timeout=10
            )
            self._conn.send_command(
                "terminal width 32767",
                expect_string=self._prompt_re, read_timeout=10
            )
            logger.info(f"Pagination disabled for {self.hostname}")
        except Exception as e:
            logger.warning(f"Failed to disable pagination: {e}")

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

    def _send(self, cmd: str, read_timeout: int = 45) -> str:
        """Send a command using the cached prompt regex for reliable detection."""
        kwargs = {"command_string": cmd, "read_timeout": read_timeout}
        if self._prompt_re:
            kwargs["expect_string"] = self._prompt_re
        return self._conn.send_command(**kwargs)

    def collect(self, on_progress=None) -> dict[str, Any]:
        """
        Connect, run all commands, parse, return unified state dict.
        Returns last good data on connection failure.
        """
        t0 = time.time()
        self._collect_count += 1
        logger.info(f"Poll #{self._collect_count} starting for {self.hostname}")

        try:
            self._ensure_connected()
        except NetmikoAuthenticationException as e:
            self._last_error = f"Auth failed: {e}"
            logger.error(self._last_error)
            return self._stale_or_error()
        except NetmikoTimeoutException as e:
            self._last_error = f"Timeout: {e}"
            logger.error(self._last_error)
            return self._stale_or_error()
        except Exception as e:
            self._last_error = f"Connection failed: {e}"
            logger.error(self._last_error)
            return self._stale_or_error()

        total_cmds = len(JSON_COMMANDS) + len(TEXT_COMMANDS) + 1  # +1 for logging
        cmd_idx = 0

        data: dict[str, Any] = {
            "meta": {
                "hostname": self.hostname,
                "poll_count": self._collect_count,
                "poll_time": None,
                "error": None,
                "timestamp": time.time(),
            }
        }

        try:
            # Run JSON commands
            for key, cmd in JSON_COMMANDS.items():
                if on_progress:
                    try:
                        on_progress(key, cmd_idx, total_cmds, time.time() - t0, "start")
                    except Exception:
                        pass
                try:
                    raw = self._send(cmd)
                    data[key] = json.loads(raw)
                except json.JSONDecodeError:
                    logger.warning(f"JSON decode failed for '{cmd}', storing raw")
                    data[key] = {"_raw": raw, "_error": "json_decode_failed"}
                except Exception as e:
                    logger.warning(f"Command failed '{cmd}': {e}")
                    data[key] = {"_error": str(e)}
                    if "socket" in str(e).lower() or "closed" in str(e).lower():
                        self._conn = None
                        break
                cmd_idx += 1
                if on_progress:
                    try:
                        on_progress(key, cmd_idx, total_cmds, time.time() - t0, "done")
                    except Exception:
                        pass

            # Run text commands
            for key, cmd in TEXT_COMMANDS.items():
                if on_progress:
                    try:
                        on_progress(key, cmd_idx, total_cmds, time.time() - t0, "start")
                    except Exception:
                        pass
                try:
                    raw = self._send(cmd)
                    if key == "environment":
                        data[key] = parse_environment(raw)
                    else:
                        data[key] = {"_raw": raw}
                except Exception as e:
                    logger.warning(f"Command failed '{cmd}': {e}")
                    data[key] = {"_error": str(e)}
                    if "socket" in str(e).lower() or "closed" in str(e).lower():
                        self._conn = None
                        break
                cmd_idx += 1
                if on_progress:
                    try:
                        on_progress(key, cmd_idx, total_cmds, time.time() - t0, "done")
                    except Exception:
                        pass

            # Logging: always text-parsed (no | json support)
            if on_progress:
                try:
                    on_progress("logging", cmd_idx, total_cmds, time.time() - t0, "start")
                except Exception:
                    pass
            data["logging"] = []
            for log_cmd in LOGGING_CMDS:
                try:
                    raw = self._send(log_cmd)
                    preview = raw[:300].replace('\n', '\\n')
                    logger.debug(f"Raw logging output ({log_cmd}): {preview}")
                    if not raw.strip():
                        logger.info(f"Empty output from '{log_cmd}', trying next")
                        continue
                    entries = parse_logging(raw)
                    logger.info(
                        f"Parsed {len(entries)} log entries from '{log_cmd}'"
                        f" (raw={len(raw)} bytes)"
                    )
                    if entries:
                        data["logging"] = entries
                        break
                    lines = [l for l in raw.splitlines() if l.strip()]
                    if lines:
                        logger.warning(
                            f"Got {len(lines)} lines from '{log_cmd}' but "
                            f"parser matched 0. Sample line: {lines[-1][:120]}"
                        )
                except Exception as e:
                    logger.warning(f"Logging command '{log_cmd}' failed: {e}")
                    if "socket" in str(e).lower() or "closed" in str(e).lower():
                        self._conn = None
                        break

            cmd_idx += 1
            if on_progress:
                try:
                    on_progress("logging", cmd_idx, total_cmds, time.time() - t0, "done")
                except Exception:
                    pass

        except Exception as e:
            logger.error(f"Unexpected error during collection: {e}")
            self._conn = None

        elapsed = time.time() - t0
        data["meta"]["poll_time"] = round(elapsed, 2)
        self._last_data = data
        self._last_error = None
        self._last_collect_time = time.time()

        logger.info(f"Poll #{self._collect_count} complete in {elapsed:.1f}s")
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
            }
        }