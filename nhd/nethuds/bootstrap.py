"""
Seed the live config dir from the packaged example configs.

`pip install` ships read-only `*.example.yaml` files inside the package.
This module copies them into the writable config dir (see paths.config_dir)
so a fresh install is editable with zero manual copying. Seeding is
idempotent: existing files are left alone unless `overwrite=True`.

The launcher auto-seeds on startup (disable with NETHUDS_NO_AUTOSEED=1).
`nethuds-init` runs the same thing explicitly.
"""

import argparse
import importlib.resources as resources
import logging
import shutil
from pathlib import Path

from .paths import config_dir

logger = logging.getLogger("nethuds.bootstrap")

# (package, example filename inside package, live filename in config dir)
_EXAMPLES = [
    ("nethuds",           "devices.example.yaml", "devices.yaml"),
    ("nethuds.arista",    "config.example.yaml",  "arista.yaml"),
    ("nethuds.juniper",   "config.example.yaml",  "juniper.yaml"),
    ("nethuds.cisco_ios", "config.example.yaml",  "cisco.yaml"),
    ("nethuds.linux",     "config.example.yaml",  "linux.yaml"),
]


def seed_config_dir(overwrite: bool = False) -> list[Path]:
    """Copy packaged examples into the config dir. Returns files written."""
    dest = config_dir()
    dest.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for pkg, example, live in _EXAMPLES:
        target = dest / live
        if target.exists() and not overwrite:
            continue
        src = resources.files(pkg) / example
        with resources.as_file(src) as real_path:
            shutil.copy(real_path, target)
        written.append(target)
    return written


def main():
    ap = argparse.ArgumentParser(
        prog="nethuds-init",
        description="Seed the nethuds config dir from packaged example configs.",
    )
    ap.add_argument("--force", action="store_true",
                    help="overwrite existing config files")
    args = ap.parse_args()
    written = seed_config_dir(overwrite=args.force)
    if written:
        print(f"Seeded {len(written)} file(s) into {config_dir()}:")
        for w in written:
            print(f"  {w}")
    else:
        print(f"Config dir {config_dir()} already populated; "
              f"nothing to do (use --force to overwrite).")


if __name__ == "__main__":
    main()
