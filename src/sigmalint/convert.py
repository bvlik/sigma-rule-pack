"""Convert parsed Sigma rules into backend query languages.

This is a small, dependency-free Sigma *backend*: it turns the ``detection``
block of a parsed rule (a plain ``dict``) into a Splunk SPL search or an
Elastic Lucene query string. It intentionally keeps YAML I/O out of here so the
logic stays pure and unit-testable.

Supported field modifiers: ``contains``, ``startswith``, ``endswith`` and plain
equality. Supported conditions: bare selection names, ``and``/``or``/``not``,
parentheses and the ``all of`` / ``1 of`` / ``any of`` quantifiers (over a
``prefix_*`` pattern or ``them``). Anything we cannot express raises
``ConvertError`` rather than emitting a silently wrong query.
"""
from __future__ import annotations

import re

SUPPORTED_TARGETS = ("splunk", "elastic")


class ConvertError(ValueError):
    """Raised when a rule uses a feature the backend cannot express."""


# --- value / field rendering ------------------------------------------------

# Lucene reserved characters that must be backslash-escaped (we keep '*' as a
# wildcard, never escaping it).
_LUCENE_SPECIAL = set('+-&|!(){}[]^"~:\\/ ')


_MATCH_MODIFIERS = ("contains", "startswith", "endswith")


def _parse_modifiers(field_key: str) -> tuple[str, str | None, bool]:
    """Split ``Field|contains|all`` into (field, match_modifier, match_all).

    ``match_all`` means a list of values must *all* match (AND) instead of the
    default any-of (OR). Unknown modifiers raise ``ConvertError``.
    """
    field, _, mod_str = field_key.partition("|")
    if not mod_str:
        return field, None, False
    mods = mod_str.split("|")
    match_all = "all" in mods
    value_mods = [m for m in mods if m != "all"]
    if not value_mods:
        return field, None, match_all
    if len(value_mods) > 1 or value_mods[0] not in _MATCH_MODIFIERS:
        raise ConvertError(f"unsupported field modifier '{mod_str}'")
    return field, value_mods[0], match_all


def _pattern(value: object, modifier: str | None) -> str:
    """Build the match pattern (with '*' wildcards) for a value + modifier."""
    s = str(value)
    if modifier == "contains":
        return f"*{s}*"
    if modifier == "startswith":
        return f"{s}*"
    if modifier == "endswith":
        return f"*{s}"
    return s


def _splunk_field_value(field: str, value: object, modifier: str | None) -> str:
    pat = _pattern(value, modifier)
    escaped = pat.replace("\\", "\\\\").replace('"', '\\"')
    return f'{field}="{escaped}"'


def _lucene_escape(pat: str) -> str:
    out = []
    for ch in pat:
        if ch == "*":  # keep wildcard
            out.append(ch)
        elif ch in _LUCENE_SPECIAL:
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def _lucene_field_value(field: str, value: object, modifier: str | None) -> str:
    return f"{field}:{_lucene_escape(_pattern(value, modifier))}"


def _render_field(field_key: str, value: object, target: str) -> str:
    """Render a single ``field|modifier: value(s)`` entry as a backend clause."""
    field, modifier, match_all = _parse_modifiers(field_key)
    render = _splunk_field_value if target == "splunk" else _lucene_field_value
    if isinstance(value, list):
        if not value:
            raise ConvertError(f"empty value list for field '{field_key}'")
        parts = [render(field, v, modifier) for v in value]
        joiner = " AND " if match_all else " OR "
        return "(" + joiner.join(parts) + ")"
    return render(field, value, modifier)


def _render_keyword(value: object, target: str) -> str:
    """A bare keyword (selection given as a list of strings, no field)."""
    s = str(value)
    if target == "splunk":
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return _lucene_escape(s)


def _render_selection(selection: object, target: str) -> str:
    """Render one named selection (a dict of fields, or a list of keywords)."""
    if isinstance(selection, dict):
        if not selection:
            raise ConvertError("empty selection")
        clauses = [_render_field(k, v, target) for k, v in selection.items()]
        joined = " AND ".join(clauses)
        return joined if len(clauses) == 1 else f"({joined})"
    if isinstance(selection, list):
        clauses = [_render_keyword(v, target) for v in selection]
        return "(" + " OR ".join(clauses) + ")"
    raise ConvertError(f"unsupported selection type: {type(selection).__name__}")


# --- condition handling -----------------------------------------------------

_QUANTIFIER = re.compile(r"\b(all|any|1|\d+)\s+of\s+(them|[A-Za-z0-9_]*\*?)", re.IGNORECASE)
_TOKEN = re.compile(r"\(|\)|\b(?:and|or|not)\b|[A-Za-z_][A-Za-z0-9_]*", re.IGNORECASE)


def _matching_selections(pattern: str, names: list[str]) -> list[str]:
    if pattern.lower() == "them":
        return list(names)
    if pattern.endswith("*"):
        prefix = pattern[:-1]
        return [n for n in names if n.startswith(prefix)]
    return [n for n in names if n == pattern]


def _expand_quantifiers(condition: str, names: list[str]) -> str:
    def repl(match: re.Match[str]) -> str:
        quant, pattern = match.group(1).lower(), match.group(2)
        targets = _matching_selections(pattern, names)
        if not targets:
            raise ConvertError(f"quantifier '{match.group(0)}' matches no selection")
        joiner = " and " if quant == "all" else " or "
        return "(" + joiner.join(targets) + ")"

    return _QUANTIFIER.sub(repl, condition)


def _condition_to_query(condition: str, rendered: dict[str, str], target: str) -> str:
    expanded = _expand_quantifiers(condition, list(rendered))
    out: list[str] = []
    for tok in _TOKEN.findall(expanded):
        low = tok.lower()
        if tok in ("(", ")"):
            out.append(tok)
        elif low in ("and", "or", "not"):
            out.append(low.upper())
        elif tok in rendered:
            out.append(rendered[tok])
        else:
            raise ConvertError(f"condition references unknown selection '{tok}'")
    # tidy spacing around parentheses
    text = " ".join(out)
    return text.replace("( ", "(").replace(" )", ")")


# Sigma aggregation tail, e.g. ``count() by src_ip > 10`` or ``count(User) >= 5``.
_AGGREGATION = re.compile(
    r"^(?P<func>count|min|max|sum|avg)\s*\(\s*(?P<aggfield>[A-Za-z0-9_.]*)\s*\)"
    r"(?:\s+by\s+(?P<group>[A-Za-z0-9_.]+))?"
    r"\s*(?P<op>[<>]=?|==)\s*(?P<threshold>\d+)\s*$",
    re.IGNORECASE,
)


def _splunk_aggregation(agg: str) -> str:
    m = _AGGREGATION.match(agg.strip())
    if not m:
        raise ConvertError(f"unsupported aggregation '{agg}'")
    func, aggfield, group = m["func"].lower(), m["aggfield"], m["group"]
    op = "=" if m["op"] == "==" else m["op"]
    if func == "count":
        metric = f"dc({aggfield}) as count" if aggfield else "count"
    else:
        metric = f"{func}({aggfield}) as count"
    by = f" by {group}" if group else ""
    return f"stats {metric}{by} | where count {op} {m['threshold']}"


def convert_detection(detection: object, target: str) -> str:
    """Convert a parsed ``detection`` block into a backend query string."""
    if target not in SUPPORTED_TARGETS:
        raise ConvertError(f"unknown target '{target}' (supported: {SUPPORTED_TARGETS})")
    if not isinstance(detection, dict):
        raise ConvertError("detection is not a mapping")
    condition = detection.get("condition")
    if not isinstance(condition, str) or not condition.strip():
        raise ConvertError("missing or empty detection.condition")
    selections = {k: v for k, v in detection.items() if k != "condition"}
    if not selections:
        raise ConvertError("detection defines no selections")

    search_cond, _, agg = condition.partition("|")
    rendered = {name: _render_selection(sel, target) for name, sel in selections.items()}
    body = _condition_to_query(search_cond, rendered, target)

    if not agg.strip():
        return f"search {body}" if target == "splunk" else body
    # The condition carries a Sigma aggregation/correlation after the pipe.
    if target == "splunk":
        return f"search {body} | {_splunk_aggregation(agg)}"
    # A Lucene query string cannot aggregate; emit the base filter and flag it.
    return f"{body}\n# aggregation not expressible in a Lucene query string: {agg.strip()}"


def convert_rule(rule: object, target: str) -> str:
    """Convert a full parsed rule, returning the backend query for its detection."""
    if not isinstance(rule, dict):
        raise ConvertError("rule is not a mapping")
    return convert_detection(rule.get("detection"), target)
