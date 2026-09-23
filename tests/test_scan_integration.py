"""End-to-end tests: scan the bundled examples and check outputs + reporters."""

import json

from tests.conftest import EXAMPLES_DIR
from warden.models import Severity
from warden.report import to_json, to_sarif
from warden.scan import scan_path


def test_full_scan_of_examples():
    result = scan_path(EXAMPLES_DIR)
    rule_ids = {f.rule_id for f in result.findings}
    # A representative finding from each parser.
    assert "AWS_S3_PUBLIC_ACL" in rule_ids
    assert "DOCKER_RUNS_AS_ROOT" in rule_ids
    assert "K8S_PRIVILEGED_CONTAINER" in rule_ids
    # Correlation produced at least the flagship chain.
    chain_ids = {c.chain_id for c in result.chains}
    assert "CHAIN_CONTAINER_TO_CLOUD_ADMIN" in chain_ids


def test_min_severity_filters_findings():
    high_only = scan_path(EXAMPLES_DIR, min_severity=Severity.HIGH)
    assert all(f.severity >= Severity.HIGH for f in high_only.findings)


def test_json_report_is_valid_and_structured():
    result = scan_path(EXAMPLES_DIR)
    payload = json.loads(to_json(result))
    assert payload["tool"] == "warden"
    assert payload["summary"]["findings"] == len(result.findings)
    assert isinstance(payload["attack_chains"], list)


def test_sarif_report_is_valid_2_1_0():
    result = scan_path(EXAMPLES_DIR)
    sarif = json.loads(to_sarif(result))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "Warden"
    # Every result references a rule that exists in the catalogue.
    catalogue = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for res in run["results"]:
        assert res["ruleId"] in catalogue
        assert res["level"] in {"error", "warning", "note"}


def test_findings_sorted_by_severity_desc():
    result = scan_path(EXAMPLES_DIR)
    severities = [int(f.severity) for f in result.findings]
    assert severities == sorted(severities, reverse=True)


def test_custom_policy_dir_is_loaded():
    import os

    from warden.rules import load_all_rules

    policies = os.path.join(os.path.dirname(EXAMPLES_DIR), "policies")
    builtin_ids = {r.id for r in load_all_rules()}
    with_custom_ids = {r.id for r in load_all_rules(policies)}
    # The custom directory adds the org-specific rules on top of the built-ins.
    assert "ORG_S3_REQUIRE_NAMING" in with_custom_ids
    assert "ORG_S3_REQUIRE_NAMING" not in builtin_ids
    assert builtin_ids < with_custom_ids


def test_custom_rule_fires_on_noncompliant_name(tmp_path):
    from warden.scan import scan_path as _scan

    tf = tmp_path / "bad.tf"
    tf.write_text('resource "aws_s3_bucket" "b" {\n  bucket = "wrongprefix-data"\n}\n')
    import os

    policies = os.path.join(os.path.dirname(EXAMPLES_DIR), "policies")
    result = _scan(str(tf), policy_dir=policies)
    assert "ORG_S3_REQUIRE_NAMING" in {f.rule_id for f in result.findings}
