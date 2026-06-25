"""
Cisco IOS data collector using Netmiko.
Connects via SSH, runs show commands, parses text output.
No JSON support — everything is regex-parsed.
"""

import logging
import re
import time
from pathlib import Path
from typing import Any

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

from .parsers import (
    parse_version,
    parse_environment,
    parse_temperature,
    parse_cpu,
    parse_interfaces_status,
    parse_lldp,
    parse_route_summary,
    parse_logging,
    parse_inventory,
    parse_spanning_tree_summary,
    parse_mac_count,
    parse_interfaces_description,
)

logger = logging.getLogger("collector")

# All commands and their parser functions
COMMANDS = {
    "version":      ("show version", parse_version),
    "environment":  ("show environment status", parse_environment),
    "temperature":  ("show environment temperature", parse_temperature),
    "cpu":          ("show processes cpu sorted", parse_cpu),
    "interfaces":   ("show interfaces status", parse_interfaces_status),
    "interfaces_desc": ("show interfaces description", parse_interfaces_description),
    "lldp":         ("show lldp neighbors", parse_lldp),
    "routes":       ("show ip route summary", parse_route_summary),
    "logging":      ("show logging", parse_logging),
    "inventory":    ("show inventory", parse_inventory),
    "stp":          ("show spanning-tree summary", parse_spanning_tree_summary),
    "mac_count":    ("show mac address-table count", parse_mac_count),
}


class CiscoCollector:
    """Collects operational state from a Cisco IOS device via Netmiko."""

    def __init__(self, device_config: dict):
        self.device_params = {
            "device_type": device_config.get("device_type", "cisco_ios"),
            "host": device_config["host"],
            "username": device_config["username"],
            "timeout": device_config.get("timeout", 45),
            "session_timeout": device_config.get("session_timeout", 60),
            "conn_timeout": device_config.get("timeout", 45),
        }
        if device_config.get("use_keys", False):
            self.device_params["use_keys"] = True
            if device_config.get("key_file"):
                self.device_params["key_file"] = str(
                    Path(device_config["key_file"]).expanduser()
                )
        if device_config.get("password"):
            self.device_params["password"] = device_config["password"]
        if device_config.get("secret"):
            self.device_params["secret"] = device_config["secret"]

        if device_config.get("legacy_ssh", False):
            self.device_params["disabled_algorithms"] = {
                "pubkeys": ["rsa-sha2-256", "rsa-sha2-512"],
            }
            logger.info(f"Legacy SSH mode enabled for {device_config['host']}")

        self.hostname = device_config["host"]
        self._conn = None
        self._prompt_re = None
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
        # Enable mode if secret is configured
        if self.device_params.get("secret"):
            self._conn.enable()
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
                "terminal width 512",
                expect_string=self._prompt_re, read_timeout=10
            )
            logger.info(f"Pagination disabled for {self.hostname}")
        except Exception as e:
            logger.warning(f"Failed to disable pagination: {e}")

    def _send(self, cmd: str, read_timeout: int = 45) -> str:
        """Send a command using the cached prompt regex for reliable detection."""
        kwargs = {"command_string": cmd, "read_timeout": read_timeout}
        if self._prompt_re:
            kwargs["expect_string"] = self._prompt_re
        return self._conn.send_command(**kwargs)

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

    def collect(self, on_progress=None) -> dict[str, Any]:
        """Run all commands over persistent session, return unified state dict."""
        t0 = time.time()
        self._collect_count += 1
        total_cmds = len(COMMANDS)
        cmd_idx = 0
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

        data: dict[str, Any] = {
            "meta": {
                "hostname": self.hostname,
                "poll_count": self._collect_count,
                "poll_time": None,
                "error": None,
                "timestamp": time.time(),
            }
        }

        for key, (cmd, parser) in COMMANDS.items():
            if on_progress:
                try:
                    on_progress(key, cmd_idx, total_cmds, time.time() - t0, "start")
                except Exception:
                    pass

            try:
                raw = self._send(cmd, read_timeout=45)
                data[key] = parser(raw)
            except Exception as e:
                logger.warning(f"Command failed '{cmd}': {e}")
                data[key] = {"_error": str(e)}
                if "socket" in str(e).lower() or "closed" in str(e).lower():
                    self._conn = None
                    cmd_idx += 1
                    if on_progress:
                        try:
                            on_progress(key, cmd_idx, total_cmds, time.time() - t0, "done")
                        except Exception:
                            pass
                    break

            cmd_idx += 1

            if on_progress:
                try:
                    on_progress(key, cmd_idx, total_cmds, time.time() - t0, "done")
                except Exception:
                    pass

        elapsed = time.time() - t0
        data["meta"]["poll_time"] = round(elapsed, 2)
        self._last_data = data
        self._last_error = None
        self._last_collect_time = time.time()

        logger.info(f"Poll #{self._collect_count} complete in {elapsed:.1f}s")
        return data

    def _stale_or_error(self) -> dict[str, Any]:
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