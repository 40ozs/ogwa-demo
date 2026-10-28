"""``python -m app.demo.genesee_press check|write|summary|overlay-check|overlay-write|verify-vendor``.

    check           exit 1 if docs/demo/genesee-press.manifest.json or config/correlation.genesee-press.json
                    differs from what the vendored projection and the overlay give
    write           regenerate both files
    summary         print the dataset's object counts
    verify-vendor   verify the vendored projection against SYNTHETIC_ENTERPRISE.lock
    overlay-check   exit 1 if config/genesee-press/ogwa-overlay.json differs from a rebuild (needs the
                    legacy Null Meridian generator, until cutover)
    overlay-write   regenerate the overlay

Pure: no store, no network, no clock. Only repository files are read.
"""

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


def _sync(files: dict[Path, str], write: bool, hint: str) -> int:
    stale = []
    for path, text in files.items():
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if current == text:
            continue
        if write:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            print(f"wrote {path.relative_to(REPO_ROOT).as_posix()}")
        else:
            stale.append(path.relative_to(REPO_ROOT).as_posix())
    if stale:
        print(f"out of date (run: python -m app.demo.genesee_press {hint}): " + ", ".join(stale), file=sys.stderr)
        return 1
    if not write:
        print("up to date")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.demo.genesee_press")
    parser.add_argument("command", choices=("check", "write", "summary", "verify-vendor", "overlay-check", "overlay-write"))
    args = parser.parse_args(argv)
    if args.command == "verify-vendor":
        from app.demo.genesee_press.projection import load

        print(json.dumps(load().source, indent=2, sort_keys=True))
        return 0
    if args.command.startswith("overlay-"):
        from app.demo.genesee_press.overlay import OVERLAY_PATH, build_overlay, render
        from app.demo.genesee_press.projection import vendored
        from app.demo.null_meridian.dataset import build_dataset as legacy

        return _sync({OVERLAY_PATH: render(build_overlay(legacy(), vendored()))}, args.command == "overlay-write",
                     "overlay-write")
    from app.demo.genesee_press.dataset import build_dataset
    from app.demo.genesee_press.manifest import generated_files

    ds = build_dataset()
    if args.command == "summary":
        print(json.dumps(ds.counts(), indent=2))
        return 0
    return _sync(generated_files(ds), args.command == "write", "write")


if __name__ == "__main__":
    raise SystemExit(main())
