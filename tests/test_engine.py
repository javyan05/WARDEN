"""Unit tests for the policy engine primitives."""

from warden.engine import Condition, Rule, get_path
from warden.models import Resource, ResourceKind, Severity


def _res(attrs):
    return Resource(
        kind=ResourceKind.TERRAFORM,
        resource_type="aws_s3_bucket",
        name="test",
        file_path="test.tf",
        attributes=attrs,
    )


def test_get_path_simple():
    assert get_path({"a": {"b": 1}}, "a.b") == [1]
    assert get_path({"a": 1}, "missing") == []


def test_get_path_fans_out_over_lists():
    obj = {"containers": [{"priv": True}, {"priv": False}]}
    assert sorted(get_path(obj, "containers.priv")) == [False, True]


def test_condition_absent_and_present():
    res = _res({"acl": "private"})
    assert Condition("acl", "present").evaluate(res) is True
    assert Condition("encryption", "absent").evaluate(res) is True
    assert Condition("acl", "absent").evaluate(res) is False


def test_condition_equals_and_in():
    res = _res({"acl": "public-read"})
    assert Condition("acl", "equals", "public-read").evaluate(res) is True
    assert Condition("acl", "in", ["public-read", "public-read-write"]).evaluate(res) is True
    assert Condition("acl", "equals", "private").evaluate(res) is False


def test_condition_truthy_falsy():
    assert Condition("flag", "truthy").evaluate(_res({"flag": True})) is True
    assert Condition("flag", "truthy").evaluate(_res({"flag": False})) is False
    # falsy is true when absent as well
    assert Condition("flag", "falsy").evaluate(_res({})) is True
    assert Condition("flag", "falsy").evaluate(_res({"flag": False})) is True


def test_condition_regex_and_contains():
    res = _res({"policy": '{"Action": "*"}', "cidrs": ["0.0.0.0/0"]})
    assert Condition("policy", "regex", r'"Action"\s*:\s*"\*"').evaluate(res) is True
    assert Condition("cidrs", "contains", "0.0.0.0/0").evaluate(res) is True


def test_condition_unknown_operator_raises():
    import pytest

    with pytest.raises(ValueError):
        Condition("x", "definitely_not_an_op").evaluate(_res({"x": 1}))


def test_rule_all_vs_any():
    res = _res({"acl": "public-read", "encrypted": False})
    rule_all = Rule(
        id="R1",
        title="t",
        severity=Severity.HIGH,
        resource_types=["aws_s3_bucket"],
        conditions=[
            Condition("acl", "equals", "public-read"),
            Condition("encrypted", "equals", True),  # false
        ],
        message="m",
        match="all",
    )
    assert rule_all.evaluate(res) is None  # not all match

    rule_any = Rule(
        id="R2",
        title="t",
        severity=Severity.HIGH,
        resource_types=["aws_s3_bucket"],
        conditions=[
            Condition("acl", "equals", "public-read"),  # true
            Condition("encrypted", "equals", True),  # false
        ],
        message="m",
        match="any",
    )
    finding = rule_any.evaluate(res)
    assert finding is not None
    assert finding.rule_id == "R2"


def test_rule_respects_resource_type():
    rule = Rule(
        id="R3",
        title="t",
        severity=Severity.LOW,
        resource_types=["aws_db_instance"],
        conditions=[Condition("acl", "present")],
        message="m",
    )
    assert rule.evaluate(_res({"acl": "x"})) is None  # wrong type
