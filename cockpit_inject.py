#!/usr/bin/env python3
"""Inject (or refresh) the NHD cockpit-layout block into each vendor HUD.

The block is delimited by BEGIN/END markers, so re-running this script
replaces an existing block rather than duplicating it. Idempotent.

Usage:
    python cockpit_inject.py [PACKAGE_ROOT] [--block BLOCK_FILE]

PACKAGE_ROOT defaults to the directory containing this script's `nhd/`.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

BEGIN = "<!-- ░░░ NHD COCKPIT LAYOUT ░░░ BEGIN"
END = "<!-- ░░░ NHD COCKPIT LAYOUT ░░░ END ░░░ -->"

VENDORS = ("arista", "cisco_ios", "juniper", "linux")


def hud_paths(root: Path) -> list[Path]:
    return [root / "nhd" / "nethuds" / v / "static" / "index.html" for v in VENDORS]


def inject(html: str, block: str) -> tuple[str, str]:
    """Return (new_html, action). action is 'inserted' | 'updated' | 'skip-no-body'."""
    if BEGIN in html and END in html:
        start = html.index(BEGIN)
        end = html.index(END) + len(END)
        new = html[:start] + block.strip() + html[end:]
        return new, "updated"
    if "</body>" not in html:
        return html, "skip-no-body"
    idx = html.rindex("</body>")
    new = html[:idx] + block.strip() + "\n" + html[idx:]
    return new, "inserted"


def main() -> int:
    ap = argparse.ArgumentParser()
    here = Path(__file__).resolve().parent
    ap.add_argument("root", nargs="?", default=str(here),
                    help="package root containing nhd/ (default: script dir)")
    ap.add_argument("--block", default=str(here / "cockpit_block.html"),
                    help="path to cockpit_block.html")
    args = ap.parse_args()

    block = Path(args.block).read_text(encoding="utf-8")
    root = Path(args.root).resolve()

    rc = 0
    for p in hud_paths(root):
        if not p.exists():
            print(f"  MISSING  {p}")
            rc = 1
            continue
        html = p.read_text(encoding="utf-8")
        new, action = inject(html, block)
        if action == "skip-no-body":
            print(f"  SKIP     {p}  (no </body>)")
            rc = 1
            continue
        if new != html:
            p.write_text(new, encoding="utf-8")
        print(f"  {action.upper():8} {p.relative_to(root)}")
    return rc


if __name__ == "__main__":
    sys.exit(main())