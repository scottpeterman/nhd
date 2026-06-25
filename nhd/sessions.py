"""
Session sources for the nethuds desktop wrapper.

A DeviceSession is the unit the UI works with: a connection bookmark that
knows which vendor HUD server should render it. Two loaders are provided:

  * load_nethuds_devices() -- reads the existing devices.yaml `devices:` list.
  * load_termtels()        -- best-effort parser for terminal-telemetry
                              session files (folder-nested or flat YAML).

The termtels field mapping is intentionally centralised in _FIELD_ALIASES
and infer_device_type() so it is trivial to correct once the exact schema
is confirmed -- nothing else in the codebase needs to change.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

# netmiko device_type -> vendor HUD key
DTYPE_TO_VENDOR: dict[str, str] = {
    "arista_eos": "arista",
    "juniper_junos": "juniper",
    "cisco_ios": "cisco",
    "cisco_xe": "cisco",
    "cisco_nxos": "cisco",
    "cisco_xr": "cisco",
    "linux": "linux",
}

# Free-text platform/vendor hint -> netmiko device_type.
# Mirrors launcher.PLATFORM_PATTERNS so imports route the same way.
_PLATFORM_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"arista|eos|dcs-|veos", re.I), "arista_eos"),
    (re.compile(r"juniper|junos|mx\d|qfx|ex\d|srx|vmx|acx", re.I), "juniper_junos"),
    (re.compile(r"cisco|ios|nx-?os|nexus|catalyst|asr|isr|ws-c|c9[0-9]", re.I), "cisco_ios"),
    (re.compile(r"linux|ubuntu|debian|centos|rhel|cumulus|vyos|alpine", re.I), "linux"),
]


def infer_device_type(hint: str) -> str:
    """Map a free-text platform/vendor/model string to a netmiko device_type."""
    if not hint:
        return "linux"
    # Already a known netmiko type? keep it.
    if hint in DTYPE_TO_VENDOR:
        return hint
    for pattern, dtype in _PLATFORM_PATTERNS:
        if pattern.search(hint):
            return dtype
    return "linux"


@dataclass
class DeviceSession:
    name: str
    host: str
    username: str = ""
    password: str = ""
    device_type: str = "linux"
    port: int = 22
    group: str = ""
    legacy_ssh: bool = False
    key_file: str = ""
    # Name of a vault credential to authenticate with. When set (and the vault
    # is unlocked) it takes precedence over inline username/password/key_file,
    # so a saved session file need carry no secret of its own. `tags` feed the
    # resolver's tag-match scoring when no credential is pinned by name.
    credential: str = ""
    tags: list[str] = field(default_factory=list)

    @property
    def vendor(self) -> str:
        """Which vendor HUD server should render this device."""
        return DTYPE_TO_VENDOR.get(self.device_type, "linux")


# ---- field alias tables (the bits to confirm against a real termtels file) ----
_FIELD_ALIASES = {
    "host":     ("host", "Host", "hostname", "Hostname", "ip", "address", "Address"),
    "name":     ("display_name", "DisplayName", "name", "Name", "label"),
    "username": ("username", "Username", "user", "User"),
    "password": ("password", "Password"),
    "port":     ("port", "Port", "ssh_port"),
    "hint":     ("device_type", "DeviceType", "Vendor", "vendor",
                 "Model", "model", "platform", "Platform", "os", "OS"),
    "legacy":   ("legacy_ssh", "LegacySSH", "legacy"),
    "keyfile":  ("key_file", "keyfile", "KeyFile", "identity_file"),
    "group":    ("folder_name", "FolderName", "group", "Group", "folder"),
    "credential": ("credential", "Credential", "cred", "credential_name"),
    "tags":     ("tags", "Tags", "labels"),
}
_CHILD_KEYS = ("sessions", "Sessions", "children", "items", "devices")


def _first(node: dict, field: str):
    for alias in _FIELD_ALIASES[field]:
        if alias in node and node[alias] not in (None, ""):
            return node[alias]
    return None


def _looks_like_device(node: dict) -> bool:
    return any(alias in node for alias in _FIELD_ALIASES["host"])


def _emit(node: dict, group: str) -> DeviceSession | None:
    host = _first(node, "host")
    if not host:
        return None
    raw_tags = _first(node, "tags")
    if isinstance(raw_tags, str):
        tags = [t.strip() for t in raw_tags.split(",") if t.strip()]
    else:
        tags = list(raw_tags) if raw_tags else []
    return DeviceSession(
        name=_first(node, "name") or str(host),
        host=str(host),
        username=_first(node, "username") or "",
        password=_first(node, "password") or "",
        device_type=infer_device_type(str(_first(node, "hint") or "")),
        port=int(_first(node, "port") or 22),
        group=group,
        legacy_ssh=bool(_first(node, "legacy") or False),
        key_file=_first(node, "keyfile") or "",
        credential=_first(node, "credential") or "",
        tags=tags,
    )


def _walk(obj, group: str, out: list[DeviceSession]) -> None:
    if isinstance(obj, dict):
        if _looks_like_device(obj):
            s = _emit(obj, group)
            if s:
                out.append(s)
            return
        # treat as a folder/container
        gname = _first(obj, "group") or group
        handled = False
        for key in _CHILD_KEYS:
            if isinstance(obj.get(key), list):
                _walk(obj[key], gname, out)
                handled = True
        if not handled:
            # generic dict-of-lists fallback
            for v in obj.values():
                if isinstance(v, (list, dict)):
                    _walk(v, gname, out)
    elif isinstance(obj, list):
        for item in obj:
            _walk(item, group, out)


def load_termtels(path: str | Path) -> list[DeviceSession]:
    """Best-effort loader for terminal-telemetry session files."""
    data = yaml.safe_load(Path(path).read_text()) or {}
    root = data
    if isinstance(data, dict):
        for key in ("sessions", "Sessions", "folders", "Folders"):
            if key in data:
                root = data[key]
                break
    out: list[DeviceSession] = []
    _walk(root, group="", out=out)
    return out


def load_termtels_groups(path: str | Path) -> list[str]:
    """Every folder name declared in a termtels file, including folders that
    hold no device. SessionStore subtracts the groups that already have a
    session to recover the *empty* folders, which the device walker can't see.
    """
    data = yaml.safe_load(Path(path).read_text()) or {}
    root = data
    if isinstance(data, dict):
        for key in ("sessions", "Sessions", "folders", "Folders"):
            if key in data:
                root = data[key]
                break
    names: list[str] = []

    def collect(obj):
        if isinstance(obj, dict):
            if _looks_like_device(obj):
                return
            g = _first(obj, "group")
            if g:
                names.append(str(g))
            for key in _CHILD_KEYS:
                if isinstance(obj.get(key), list):
                    for it in obj[key]:
                        collect(it)
        elif isinstance(obj, list):
            for it in obj:
                collect(it)

    collect(root)
    return names


def load_nethuds_devices(path: str | Path) -> list[DeviceSession]:
    """Loader for the existing nethuds devices.yaml `devices:` block."""
    data = yaml.safe_load(Path(path).read_text()) or {}
    out: list[DeviceSession] = []
    for d in data.get("devices", []):
        host = d.get("host")
        if not host:
            continue
        out.append(DeviceSession(
            name=d.get("name") or str(host),
            host=str(host),
            username=d.get("username", ""),
            password=d.get("password", ""),
            device_type=d.get("device_type") or infer_device_type(d.get("platform", "")),
            port=int(d.get("port", 22)),
            group=d.get("group", ""),
            legacy_ssh=bool(d.get("legacy_ssh", False)),
            key_file=d.get("key_file", ""),
            credential=d.get("credential", ""),
            tags=list(d.get("tags", []) or []),
        ))
    return out