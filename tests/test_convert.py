"""Tests for the pure Sigma -> backend converter (no YAML files needed)."""
import pytest

from sigmalint.convert import ConvertError, convert_detection, convert_rule


def _det(**kw):
    return kw


def test_single_selection_plain_equality_splunk():
    det = _det(selection={"eventName": "CreateUser"}, condition="selection")
    assert convert_detection(det, "splunk") == 'search eventName="CreateUser"'


def test_single_selection_plain_equality_elastic():
    det = _det(selection={"eventName": "CreateUser"}, condition="selection")
    assert convert_detection(det, "elastic") == "eventName:CreateUser"


def test_endswith_becomes_leading_wildcard_splunk():
    det = _det(selection={"Image|endswith": "\\powershell.exe"}, condition="selection")
    # backslash doubled inside the Splunk quoted value
    assert convert_detection(det, "splunk") == r'search Image="*\\powershell.exe"'


def test_endswith_escapes_backslash_in_lucene():
    det = _det(selection={"Image|endswith": "\\powershell.exe"}, condition="selection")
    assert convert_detection(det, "elastic") == r"Image:*\\powershell.exe"


def test_contains_wraps_both_sides():
    det = _det(selection={"CommandLine|contains": "-enc"}, condition="selection")
    assert convert_detection(det, "splunk") == 'search CommandLine="*-enc*"'


def test_startswith_trailing_wildcard():
    det = _det(selection={"CommandLine|startswith": "powershell"}, condition="selection")
    assert convert_detection(det, "elastic") == "CommandLine:powershell*"


def test_list_value_becomes_or_group():
    det = _det(
        selection={"eventName": ["CreateUser", "CreateAccessKey"]},
        condition="selection",
    )
    assert convert_detection(det, "splunk") == (
        'search (eventName="CreateUser" OR eventName="CreateAccessKey")'
    )


def test_multiple_fields_in_selection_are_anded():
    det = _det(
        selection={"eventSource": "iam.amazonaws.com", "eventName": "CreateUser"},
        condition="selection",
    )
    out = convert_detection(det, "splunk")
    assert out == 'search (eventSource="iam.amazonaws.com" AND eventName="CreateUser")'


def test_all_of_selection_wildcard_expands_to_and():
    det = _det(
        selection_dl={"CommandLine|contains": "curl"},
        selection_pipe={"CommandLine|contains": "| bash"},
        condition="all of selection_*",
    )
    out = convert_detection(det, "splunk")
    assert out == 'search (CommandLine="*curl*" AND CommandLine="*| bash*")'


def test_one_of_selection_wildcard_expands_to_or():
    det = _det(
        selection_a={"a": "1"},
        selection_b={"b": "2"},
        condition="1 of selection_*",
    )
    out = convert_detection(det, "elastic")
    assert out == "(a:1 OR b:2)"


def test_and_not_filter_condition():
    det = _det(
        selection={"EventID": "4624"},
        filter={"User": "SYSTEM"},
        condition="selection and not filter",
    )
    out = convert_detection(det, "splunk")
    assert out == 'search EventID="4624" AND NOT User="SYSTEM"'


def test_all_of_them():
    det = _det(
        sel1={"a": "1"},
        sel2={"b": "2"},
        condition="all of them",
    )
    assert convert_detection(det, "elastic") == "(a:1 AND b:2)"


def test_lucene_escapes_spaces_and_specials():
    det = _det(selection={"CommandLine|contains": " -enc "}, condition="selection")
    assert convert_detection(det, "elastic") == r"CommandLine:*\ \-enc\ *"


def test_keyword_list_selection():
    det = _det(keywords=["mimikatz", "sekurlsa"], condition="keywords")
    assert convert_detection(det, "splunk") == 'search ("mimikatz" OR "sekurlsa")'


def test_unknown_target_raises():
    det = _det(selection={"a": "1"}, condition="selection")
    with pytest.raises(ConvertError):
        convert_detection(det, "kibana")


def test_unsupported_modifier_raises():
    det = _det(selection={"field|re": "^x$"}, condition="selection")
    with pytest.raises(ConvertError):
        convert_detection(det, "splunk")


def test_quantifier_matching_nothing_raises():
    det = _det(selection={"a": "1"}, condition="all of filter_*")
    with pytest.raises(ConvertError):
        convert_detection(det, "splunk")


def test_unknown_selection_in_condition_raises():
    det = _det(selection={"a": "1"}, condition="selection and ghost")
    with pytest.raises(ConvertError):
        convert_detection(det, "splunk")


def test_missing_condition_raises():
    with pytest.raises(ConvertError):
        convert_detection({"selection": {"a": "1"}}, "splunk")


def test_contains_all_modifier_joins_with_and():
    det = _det(
        selection={"CommandLine|contains|all": ["MiniDump", "comsvcs"]},
        condition="selection",
    )
    out = convert_detection(det, "splunk")
    assert out == 'search (CommandLine="*MiniDump*" AND CommandLine="*comsvcs*")'


def test_aggregation_splunk_emits_stats_and_where():
    det = _det(
        selection=["Failed password for"],
        condition="selection | count() by src_ip > 10",
    )
    out = convert_detection(det, "splunk")
    assert out == 'search ("Failed password for") | stats count by src_ip | where count > 10'


def test_aggregation_count_field_uses_distinct_count():
    det = _det(selection={"a": "1"}, condition="selection | count(User) by host >= 5")
    out = convert_detection(det, "splunk")
    assert out == 'search a="1" | stats dc(User) as count by host | where count >= 5'


def test_aggregation_elastic_flags_unexpressible():
    det = _det(selection={"a": "1"}, condition="selection | count() by src_ip > 10")
    out = convert_detection(det, "elastic")
    assert out.startswith("a:1\n# aggregation not expressible")


def test_unparseable_aggregation_raises():
    det = _det(selection={"a": "1"}, condition="selection | weird_agg()")
    with pytest.raises(ConvertError):
        convert_detection(det, "splunk")


def test_convert_rule_uses_detection_block():
    rule = {
        "title": "x",
        "detection": {"selection": {"eventName": "CreateUser"}, "condition": "selection"},
    }
    assert convert_rule(rule, "splunk") == 'search eventName="CreateUser"'
