"""
Juniper JUNOS data collector using Netmiko.
Connects via SSH, runs show commands with '| display xml',
parses XML into the same dict structure that '| display json'
would produce, so the frontend jval/jnum/jattr helpers work unchanged.

Supports legacy JunOS versions that lack '| display json'.
"""

import logging
import re
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

logger = logging.getLogger("collector")


# Commands using '| display xml' (universal JunOS support)
COMMANDS = {
    "version":        "show version | display xml | no-more",
    "routing_engine": "show chassis routing-engine | display xml | no-more",
    "environment":    "show chassis environment | display xml | no-more",
    "hardware":       "show chassis hardware | display xml | no-more",
    "bgp":            "show bgp summary | display xml | no-more",
    "ospf":           "show ospf neighbor | display xml | no-more",
    "lldp":           "show lldp neighbors | display xml | no-more",
    "routes":         "show route summary | display xml | no-more",
    "interfaces":     "show interfaces | display xml | no-more",
    "optics":         "show interfaces diagnostics optics | display xml | no-more",
    "alarms":         "show system alarm | display xml | no-more",
}

TEXT_COMMANDS = {
    "logging": "show log messages | last 30",
}


def xml_to_juniper_dict(element):
    """
    Convert an XML ElementTree element into the same dict structure
    that Juniper's '| display json' produces.

    Rules (matching Juniper JSON output):
    - Leaf element (text only) → [{"data": "text", "attributes": {...}}]
    - Branch element (has children) → [{child_tag: ..., child_tag: ...}]
    - Multiple siblings with same tag → appended to same list
    - XML attributes (like junos:celsius) preserved in "attributes" dict

    The frontend jval/jnum/jattr helpers consume this format.
    """
    children = list(element)

    if not children:
        # Leaf node — wrap as [{"data": "text", "attributes": {}}]
        entry = {"data": (element.text or "").strip()}
        # Preserve XML attributes (e.g. junos:celsius="45")
        if element.attrib:
            attrs = {}
            for k, v in element.attrib.items():
                # Strip namespace URI, keep local name
                # {http://xml.juniper.net/junos/...}celsius → junos:celsius
                if k.startswith("{"):
                    ns_end = k.index("}")
                    local = k[ns_end + 1:]
                    attrs[f"junos:{local}"] = v
                else:
                    attrs[k] = v
            entry["attributes"] = attrs
        return [entry]

    # Branch node — group children by tag
    result = {}
    for child in children:
        # Strip namespace from tag
        tag = child.tag
        if tag.startswith("{"):
            tag = tag[tag.index("}") + 1:]

        converted = xml_to_juniper_dict(child)

        if tag in result:
            # Same tag seen before — extend the list (multiple siblings)
            if isinstance(result[tag], list) and len(result[tag]) > 0 and isinstance(result[tag][0], dict) and "data" in result[tag][0]:
                # Previous was a leaf, this is a sibling leaf
                result[tag].extend(converted)
            elif isinstance(converted, list) and len(converted) > 0 and isinstance(converted[0], dict) and "data" in converted[0]:
                # New is a leaf
                result[tag].extend(converted)
            else:
                # Both are branch nodes — append to list
                result[tag].extend(converted)
        else:
            result[tag] = converted

    return [result]


def parse_xml_output(raw: str) -> dict:
    """
    Parse raw XML output from a Juniper CLI command.
    Strips the <rpc-reply> wrapper and returns the inner content
    in Juniper JSON-equivalent dict format.
    """
    # Clean up: remove any leading/trailing non-XML content
    # (Netmiko sometimes includes prompt artifacts)
    raw = raw.strip()

    # Find the XML content
    xml_start = raw.find("<?xml") if "<?xml" in raw else raw.find("<rpc-reply")
    if xml_start < 0:
        xml_start = raw.find("<")
    if xml_start < 0:
        return {"_raw": raw, "_error": "no_xml_found"}

    raw = raw[xml_start:]

    # Remove trailing prompt/garbage after closing tag
    for end_tag in ["</rpc-reply>", "</output>"]:
        idx = raw.find(end_tag)
        if idx >= 0:
            raw = raw[: idx + len(end_tag)]
            break

    try:
        # Strip namespaces for easier parsing
        raw_clean = re.sub(r'\sxmlns[^"]*"[^"]*"', '', raw)
        raw_clean = re.sub(r'\sjunos:[a-z]+="', ' junos:', raw_clean)
        # Fix the attribute quoting we just broke
        raw_clean = re.sub(r' junos:([^=]+)$', '', raw_clean)

        root = ET.fromstring(raw)
    except ET.ParseError:
        # Try with namespace stripping
        try:
            cleaned = re.sub(r'\sxmlns(?::[^=]*)?\s*=\s*"[^"]*"', '', raw)
            root = ET.fromstring(cleaned)
        except ET.ParseError as e:
            return {"_raw": raw[:500], "_error": f"xml_parse_failed: {e}"}

    # Unwrap <rpc-reply> if present
    tag = root.tag
    if "}" in tag:
        tag = tag[tag.index("}") + 1:]

    if tag == "rpc-reply":
        # Return all children merged into one dict
        result = {}
        for child in root:
            child_tag = child.tag
            if "}" in child_tag:
                child_tag = child_tag[child_tag.index("}") + 1:]
            result[child_tag] = xml_to_juniper_dict(child)
        return result
    else:
        # Single top-level element
        return {tag: xml_to_juniper_dict(root)}


def parse_logging_text(raw: str) -> list[dict[str, Any]]:
    """Parse Juniper syslog text output into structured entries."""
    entries = []
    # Structured syslog with facility/severity
    struct_pat = re.compile(
        r"^(\w+\s+\d+\s+[\d:]+)\s+"
        r"(\S+)\s+"
        r"(\S+)\[?\d*\]?:\s+"
        r"%(\S+?)-(\d)-(\S+?):\s+"
        r"(.+)$",
        re.MULTILINE,
    )
    # Generic log format
    log_pat = re.compile(
        r"^(\w+\s+\d+\s+[\d:]+)\s+"
        r"(\S+)\s+"
        r"(\S+?):\s+"
        r"(.+)$",
        re.MULTILINE,
    )

    for m in struct_pat.finditer(raw):
        entries.append({
            "timestamp": m.group(1),
            "host": m.group(2),
            "source": m.group(3),
            "facility": m.group(4),
            "severity": int(m.group(5)),
            "mnemonic": m.group(6),
            "message": m.group(7).strip(),
        })

    if not entries:
        for m in log_pat.finditer(raw):
            entries.append({
                "timestamp": m.group(1),
                "host": m.group(2),
                "source": m.group(3),
                "facility": "",
                "severity": 6,
                "mnemonic": "",
                "message": m.group(4).strip(),
            })

    return entries


class JuniperCollector:
    """Collects operational state from a Juniper JUNOS device via Netmiko."""

    def __init__(self, device_config: dict):
        self.device_params = {
            "device_type": device_config.get("device_type", "juniper_junos"),
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

        if device_config.get("legacy_ssh", False):
            self.device_params["disabled_algorithms"] = {
                "pubkeys": ["rsa-sha2-256", "rsa-sha2-512"],
            }
            logger.info(f"Legacy SSH mode enabled for {device_config['host']}")

        self.hostname = device_config["host"]
        self._conn = None
        self._prompt_re: str | None = None
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
            # Dead session — clean up
            try:
                self._conn.disconnect()
            except Exception:
                pass
            self._conn = None
            self._prompt_re = None
            logger.info(f"Session to {self.hostname} dropped, reconnecting")

        self._conn = ConnectHandler(**self.device_params)
        raw_prompt = self._conn.find_prompt().strip()
        # Juniper VC/RE boxes may return multi-line prompts like:
        #   {master:0}\nuser@host>
        # Use only the last line for prompt matching
        _prompt = raw_prompt.splitlines()[-1].strip()
        self._prompt_re = re.escape(_prompt.rstrip(">#%")) + "[>#%]\\s*$"
        logger.info(f"Persistent session to {self.hostname}, prompt: '{_prompt}'")

        # Disable pagination at the terminal level — more reliable than
        # appending '| no-more' to every command, especially on older JunOS
        try:
            self._conn.send_command(
                "set cli screen-length 0",
                expect_string=self._prompt_re, read_timeout=10
            )
            self._conn.send_command(
                "set cli screen-width 0",
                expect_string=self._prompt_re, read_timeout=10
            )
            logger.info(f"Pagination disabled for {self.hostname}")
        except Exception as e:
            logger.warning(f"Failed to disable pagination: {e}")
    def test_connect(self):
        """Test SSH connectivity. Raises on failure, establishes persistent session on success."""
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
        """Run all commands over persistent session, return unified state dict.

        Args:
            on_progress: Optional callback(key, index, total, elapsed) called
                         after each command completes.
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
            # Run XML commands
            total_cmds = len(COMMANDS) + len(TEXT_COMMANDS)
            cmd_idx = 0
            for key, cmd in COMMANDS.items():
                if on_progress:
                    try:
                        on_progress(key, cmd_idx, total_cmds, time.time() - t0, "start")
                    except Exception:
                        pass
                try:
                    rt = 90 if key in ("interfaces", "optics", "environment", "hardware") else 45
                    raw = self._send(cmd, read_timeout=rt)
                    parsed = parse_xml_output(raw)
                    if "_error" in parsed:
                        logger.warning(f"XML parse issue for '{cmd}': {parsed.get('_error')}")
                    data[key] = parsed
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
            if self._conn is not None:
                for key, cmd in TEXT_COMMANDS.items():
                    if on_progress:
                        try:
                            on_progress(key, cmd_idx, total_cmds, time.time() - t0, "start")
                        except Exception:
                            pass
                    try:
                        raw = self._send(cmd, read_timeout=30)
                        if key == "logging":
                            data[key] = parse_logging_text(raw)
                        else:
                            data[key] = {"_raw": raw}
                    except Exception as e:
                        logger.warning(f"Command failed '{cmd}': {e}")
                        data[key] = {"_error": str(e)}
                    cmd_idx += 1
                    if on_progress:
                        try:
                            on_progress(key, cmd_idx, total_cmds, time.time() - t0, "done")
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