"""Tests for the pure Sigma validator (no YAML files needed)."""
import copy

from sigmalint.validate import validate_rule, validate_rules

VALID = {
    "title": "Whoami execution",
    "id": "8f9e2b1a-1c2d-4e3f-9a0b-1c2d3e4f5a6b",
    "status": "experimental",
    "level": "low",
    "logsource": {"product": "windows", "category": "process_creation"},
    "detection": {
        "selection": {"Image|endswith": "\\whoami.exe"},
        "condition": "selection",
    },
}


def test_valid_rule_has_no_errors():
    assert validate_rule(VALID) == []


def test_missing_title_is_flagged():
    rule = copy.deepcopy(VALID)
    del rule["title"]
    assert any("title" in e for e in validate_rule(rule))


def test_invalid_uuid_is_flagged():
    rule = copy.deepcopy(VALID)
    rule["id"] = "not-a-uuid"
    assert any("id" in e for e in validate_rule(rule))


def test_invalid_level_is_flagged():
    rule = copy.deepcopy(VALID)
    rule["level"] = "spicy"
    assert any("level" in e for e in validate_rule(rule))


def test_logsource_must_have_a_dimension():
    rule = copy.deepcopy(VALID)
    rule["logsource"] = {"definition": "free text only"}
    assert any("logsource" in e for e in validate_rule(rule))


def test_condition_referencing_unknown_selection():
    rule = copy.deepcopy(VALID)
    rule["detection"]["condition"] = "selection and filter"
    errs = validate_rule(rule)
    assert any("undefined selection 'filter'" in e for e in errs)


def test_condition_wildcard_group_is_accepted():
    rule = copy.deepcopy(VALID)
    rule["detection"] = {
        "selection_cmd": {"CommandLine|contains": "MiniDump"},
        "selection_img": {"Image|endswith": "\\rundll32.exe"},
        "condition": "all of selection_*",
    }
    assert validate_rule(rule) == []


def test_aggregation_condition_after_pipe_is_ignored():
    rule = copy.deepcopy(VALID)
    rule["detection"]["condition"] = "selection | count() by src_ip > 10"
    # 'count', 'by', 'src_ip' are aggregation fields, not selections -> no error.
    assert validate_rule(rule) == []


def test_not_a_mapping():
    assert validate_rule(["not", "a", "dict"]) == ["rule is not a mapping/object"]


def test_duplicate_ids_across_pack():
    a = ("a.yml", copy.deepcopy(VALID))
    b = ("b.yml", copy.deepcopy(VALID))  # same id
    results = validate_rules([a, b])
    assert "b.yml" in results
    assert any("duplicate id" in e for e in results["b.yml"])


def test_validate_rules_omits_clean_rules():
    results = validate_rules([("ok.yml", copy.deepcopy(VALID))])
    assert results == {}
