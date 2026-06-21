"""CLI: validate every Sigma rule under one or more paths.

    python -m sigmalint rules/
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from collections import Counter

import yaml

from .convert import SUPPORTED_TARGETS, ConvertError, convert_rule
from .validate import validate_rules


def _print_stats(loaded: list[tuple[str, object]]) -> None:
    levels: Counter[str] = Counter()
    platforms: Counter[str] = Counter()
    for _name, rule in loaded:
        if not isinstance(rule, dict):
            continue
        levels[str(rule.get("level", "unknown"))] += 1
        ls = rule.get("logsource") or {}
        platforms[str(ls.get("product") or ls.get("service") or "unknown")] += 1
    print(f"Rules: {len(loaded)}")
    print("By level:    " + ", ".join(f"{k}={v}" for k, v in sorted(levels.items())))
    print("By platform: " + ", ".join(f"{k}={v}" for k, v in sorted(platforms.items())))


def _convert(loaded: list[tuple[str, object]], target: str) -> int:
    failures = 0
    for name, rule in loaded:
        title = rule.get("title") if isinstance(rule, dict) else None
        print(f"# {title or name}")
        try:
            print(convert_rule(rule, target))
        except ConvertError as exc:
            print(f"[REJECT] cannot convert {name}: {exc}", file=sys.stderr)
            failures += 1
        print()
    if failures:
        print(f"{failures} rule(s) could not be converted.", file=sys.stderr)
        return 1
    return 0


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
    parser.add_argument("--stats", action="store_true", help="Print rule counts by level/platform and exit.")
    parser.add_argument(
        "--convert",
        choices=SUPPORTED_TARGETS,
        metavar="TARGET",
        help=f"Convert rules to a backend query and exit (one of: {', '.join(SUPPORTED_TARGETS)}).",
    )
    args = parser.parse_args(argv)
    paths = args.paths or ["rules"]

    loaded = [_load(p) for p in _iter_rule_files(paths)]
    if not loaded:
        print("[REJECT] no rule files found", file=sys.stderr)
        return 1

    if args.stats:
        _print_stats(loaded)
        return 0

    if args.convert:
        return _convert(loaded, args.convert)

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
