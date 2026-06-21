"""CLI: validate every Sigma rule under one or more paths.

    python -m sigmalint rules/
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from .validate import validate_rules


def _iter_rule_files(paths: list[str]):
    for p in paths:
        path = Path(p)
        if path.is_dir():
            yield from sorted(path.rglob("*.yml"))
            yield from sorted(path.rglob("*.yaml"))
        elif path.is_file():
            yield path


def _load(path: Path) -> tuple[str, object]:
    try:
        with path.open(encoding="utf-8") as fh:
            return (str(path), yaml.safe_load(fh))
    except yaml.YAMLError as exc:  # malformed YAML -> surface as a validation error
        return (str(path), {"__yaml_error__": str(exc)})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sigmalint",
        description="Validate Sigma detection rules (structure, ids, condition references).",
    )
    parser.add_argument("paths", nargs="*", default=["rules"], help="Rule files or directories")
    args = parser.parse_args(argv)
    paths = args.paths or ["rules"]

    loaded = [_load(p) for p in _iter_rule_files(paths)]
    if not loaded:
        print("[REJECT] no rule files found", file=sys.stderr)
        return 1

    results = validate_rules([(n, r) for n, r in loaded])
    total = len(loaded)
    bad = len(results)

    if not results:
        print(f"[PASS] {total} rule(s) valid.")
        return 0

    for name, errors in sorted(results.items()):
        print(f"[REJECT] {name}")
        for err in errors:
            print(f"    - {err}")
    print(f"\n{bad}/{total} rule(s) invalid.", file=sys.stderr)
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
