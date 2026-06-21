"""Pure validation logic for Sigma rules.

A Sigma rule is given as an already-parsed ``dict`` (we keep YAML I/O out of here
so every rule can validate the structure without touching the filesystem).
``validate_rule`` returns a list of human-readable error strings — empty means valid.
"""
from __future__ import annotations

import re
import uuid

VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
VALID_STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}

# Tokens in a Sigma `condition` that are operators/keywords, not selection names.
_CONDITION_KEYWORDS = {"and", "or", "not", "of", "them", "all", "1", "any"}
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# Pack quality gates (stricter than the bare Sigma spec, on purpose).
_DATE = re.compile(r"^\d{4}/\d{2}/\d{2}$")
# An ATT&CK technique tag, e.g. attack.t1003 or attack.t1003.001
_ATTACK_TECHNIQUE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")


def _is_uuid(value: object) -> bool:
    try:
        uuid.UUID(str(value))
        return True
    except (ValueError, AttributeError, TypeError):
        return False


def _referenced_names(condition: str) -> set[str]:
    """Selection names a condition refers to (keywords and numbers stripped out).

    Only the search expression before a ``|`` is considered; anything after the
    pipe is a Sigma aggregation/correlation that references field names, not
    selections, so it must not be checked against the defined selections.
    """
    search_expr = condition.split("|", 1)[0]
    names = set()
    for tok in _IDENTIFIER.findall(search_expr):
        if tok.lower() in _CONDITION_KEYWORDS:
            continue
        names.add(tok)
    return names


def _matches_defined(name: str, defined: set[str]) -> bool:
    """A referenced name may be a literal selection or a `prefix_*` wildcard group."""
    if name in defined:
        return True
    if name.endswith("_") or "*" in name:
        prefix = name.rstrip("*").rstrip("_")
        return any(d.startswith(prefix) for d in defined)
    # `1 of selection*` arrives here as the bare prefix when written without `_`
    return any(d == name or d.startswith(name) for d in defined)


def validate_rule(rule: object) -> list[str]:
    """Validate a single parsed Sigma rule. Returns a list of error messages."""
    errors: list[str] = []
    if not isinstance(rule, dict):
        return ["rule is not a mapping/object"]

    title = rule.get("title")
    if not isinstance(title, str) or not title.strip():
        errors.append("missing or empty 'title'")
    elif len(title) > 256:
        errors.append("'title' exceeds 256 characters")

    if not _is_uuid(rule.get("id")):
        errors.append("missing or invalid 'id' (must be a UUID)")

    status = rule.get("status")
    if status is not None and status not in VALID_STATUS:
        errors.append(f"invalid 'status': {status!r} (allowed: {sorted(VALID_STATUS)})")

    level = rule.get("level")
    if level not in VALID_LEVELS:
        errors.append(f"missing or invalid 'level': {level!r} (allowed: {sorted(VALID_LEVELS)})")

    logsource = rule.get("logsource")
    if not isinstance(logsource, dict) or not logsource:
        errors.append("missing or empty 'logsource'")
    elif not any(k in logsource for k in ("product", "service", "category")):
        errors.append("'logsource' must set at least one of product/service/category")

    # --- pack quality gates -------------------------------------------------
    if not (isinstance(rule.get("description"), str) and rule["description"].strip()):
        errors.append("missing 'description'")

    if not (isinstance(rule.get("author"), str) and rule["author"].strip()):
        errors.append("missing 'author'")

    refs = rule.get("references")
    if not (isinstance(refs, list) and refs):
        errors.append("missing 'references' (at least one source URL)")

    date = rule.get("date")
    if date is not None and not _DATE.match(str(date)):
        errors.append(f"invalid 'date' format {date!r} (expected YYYY/MM/DD)")

    tags = rule.get("tags")
    if tags is not None:
        if not isinstance(tags, list):
            errors.append("'tags' must be a list")
        else:
            malformed = [t for t in tags if str(t).startswith("attack.t") and not _ATTACK_TECHNIQUE.match(str(t))]
            for t in malformed:
                errors.append(f"malformed ATT&CK technique tag '{t}' (expected attack.tNNNN[.NNN])")

    detection = rule.get("detection")
    if not isinstance(detection, dict):
        errors.append("missing 'detection' block")
        return errors

    condition = detection.get("condition")
    selections = {k: v for k, v in detection.items() if k != "condition"}
    if not selections:
        errors.append("'detection' defines no selections")
    if not isinstance(condition, str) or not condition.strip():
        errors.append("missing or empty 'detection.condition'")
    else:
        defined = set(selections)
        for name in _referenced_names(condition):
            if not _matches_defined(name, defined):
                errors.append(f"condition references undefined selection '{name}'")

    return errors


def validate_rules(rules: list[tuple[str, object]]) -> dict[str, list[str]]:
    """Validate many rules and also flag duplicate IDs across the pack.

    ``rules`` is a list of ``(source_name, parsed_rule)`` tuples. The result maps each
    source name to its list of errors (sources with no errors are omitted). Duplicate
    ids *and* duplicate titles across the pack are reported.
    """
    results: dict[str, list[str]] = {}
    seen_ids: dict[str, str] = {}
    seen_titles: dict[str, str] = {}
    for name, rule in rules:
        errors = validate_rule(rule)
        if isinstance(rule, dict):
            rid = rule.get("id")
            if _is_uuid(rid):
                rid = str(rid)
                if rid in seen_ids:
                    errors = errors + [f"duplicate id {rid} (also in {seen_ids[rid]})"]
                else:
                    seen_ids[rid] = name
            title = rule.get("title")
            if isinstance(title, str) and title.strip():
                key = title.strip().lower()
                if key in seen_titles:
                    errors = errors + [f"duplicate title {title!r} (also in {seen_titles[key]})"]
                else:
                    seen_titles[key] = name
        if errors:
            results[name] = errors
    return results
