"""``python -m app.demo.null_meridian check|write|summary``: the committed Null Meridian files.

    check     exit 1 if docs/demo/null-meridian.manifest.json or config/correlation.null-meridian.json
              differs from what the seed generates
    write     regenerate both files
    summary   print the dataset's object counts

Pure generation: no store, no network, no configuration is read.
"""

import argparse
import json
import sys

from app.demo.null_meridian.dataset import build_dataset
from app.demo.null_meridian.manifest import REPO_ROOT, generated_files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.demo.null_meridian")
    parser.add_argument("command", choices=("check", "write", "summary"))
    args = parser.parse_args(argv)
    ds = build_dataset()
    if args.command == "summary":
        print(json.dumps(ds.counts(), indent=2))
        return 0
    stale = []
    for path, text in generated_files(ds).items():
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if current == text:
            continue
        if args.command == "write":
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            print(f"wrote {path.relative_to(REPO_ROOT).as_posix()}")
        else:
            stale.append(path.relative_to(REPO_ROOT).as_posix())
    if stale:
        print("out of date (run: python -m app.demo.null_meridian write): " + ", ".join(stale), file=sys.stderr)
        return 1
    if args.command == "check":
        print("up to date")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
