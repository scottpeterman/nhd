"""
Config path resolution for nethuds.

Live (writable) config is resolved out of the installed package so a
pip install never tries to write into site-packages. Resolution order:

  1. $NETHUDS_CONFIG_DIR        (explicit override; what Docker/systemd set)
  2. ./nethuds/                 (a config dir next to the cwd, if present)
  3. $XDG_CONFIG_HOME/nethuds   (falls back to ~/.config/nethuds)

Read-only example configs ship inside each package and are used as a
fallback when no live config exists yet, so a fresh install still boots.
"""

import os
from pathlib import Path

import yaml


def config_dir() -> Path:
    """Return the directory holding live (writable) config."""
    env = os.environ.get("NETHUDS_CONFIG_DIR")
    if env:
        return Path(env).expanduser()
    local = Path.cwd() / "nethuds"
    if local.exists():
        return local
    base = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    return Path(base) / "nethuds"


def load_yaml_config(live_name: str, example_path: Path) -> dict:
    """
    Load `<config_dir>/<live_name>` if it exists, otherwise fall back to
    the packaged example. Returns an empty dict for an empty file.
    """
    live = config_dir() / live_name
    path = live if live.exists() else Path(example_path)
    with open(path) as f:
        return yaml.safe_load(f) or {}


def save_yaml_config(live_name: str, data: dict) -> Path:
    """Write `data` to `<config_dir>/<live_name>`, creating the dir."""
    cfg_dir = config_dir()
    cfg_dir.mkdir(parents=True, exist_ok=True)
    path = cfg_dir / live_name
    with open(path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    return path
