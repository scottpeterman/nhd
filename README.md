#!/usr/bin/env python3
"""Preflight a README before a PyPI upload.

PyPI renders the long-description with no repo context, so any *relative* image
path renders broken. This catches that (and, with --check-urls, dead links)
BEFORE you build and upload an immutable version.

Usage:
    python preflight_readme.py README.md              # offline: flag relative refs
    python preflight_readme.py README.md --check-urls # also HEAD every absolute URL

Exit code is non-zero if anything is wrong, so it can gate a release in CI:
    python preflight_readme.py README.md --check-urls || exit 1
"""
import re
import sys
import argparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

IMG_HTML = re.compile(r'<img[^>]*\bsrc="([^"]+)"', re.IGNORECASE)
IMG_MD = re.compile(r'!\[[^\]]*\]\(([^)\s]+)')


def collect_image_refs(text: str):
    return [(m, "html") for m in IMG_HTML.findall(text)] + \
           [(m, "md") for m in IMG_MD.findall(text)]


def is_absolute(url: str) -> bool:
    return url.startswith(("http://", "https://"))


def check_url(url: str):
    """Return (ok, detail). ok=True means 200 + an image content-type."""
    try:
        req = Request(url, method="HEAD", headers={"User-Agent": "preflight"})
        with urlopen(req, timeout=15) as r:
            ct = r.headers.get("Content-Type", "")
            ok = r.status == 200 and ct.startswith("image/")
            return ok, f"{r.status} {ct or '?'}"
    except HTTPError as e:
        return False, f"{e.code} {e.reason}"
    except URLError as e:
        return False, f"unreachable: {e.reason}"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("readme")
    ap.add_argument("--check-urls", action="store_true",
                    help="HEAD each absolute URL and require 200 + image/* content-type")
    args = ap.parse_args(argv)

    text = open(args.readme, encoding="utf-8").read()
    refs = collect_image_refs(text)
    if not refs:
        print("no image references found"); return 0

    problems = 0
    for url, kind in refs:
        if not is_absolute(url):
            print(f"  [RELATIVE] ({kind}) {url}   <-- breaks on PyPI")
            problems += 1
            continue
        if args.check_urls:
            ok, detail = check_url(url)
            tag = "OK      " if ok else "DEAD    "
            if not ok:
                problems += 1
            print(f"  [{tag}] ({kind}) {url}  -> {detail}")
        else:
            print(f"  [absolute] ({kind}) {url}")

    print()
    if problems:
        print(f"FAIL: {problems} image reference(s) would break on PyPI")
        return 1
    print(f"PASS: all {len(refs)} image references are absolute"
          + (" and live" if args.check_urls else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())