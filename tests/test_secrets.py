"""Tests for the hardcoded-secret scanner."""

from warden.scanners.secrets import scan_text


def test_detects_aws_access_key():
    findings = scan_text("f.tf", 'access_key = "AKIAIOSFODNN7EXAMPLE"')
    assert any(f.rule_id == "SECRET_AWS_ACCESS_KEY" for f in findings)


def test_detects_private_key_header():
    findings = scan_text("id_rsa", "-----BEGIN RSA PRIVATE KEY-----")
    assert any(f.rule_id == "SECRET_PRIVATE_KEY" for f in findings)


def test_detects_generic_password():
    findings = scan_text("f.yaml", 'password: "Sup3rS3cretValue!"')
    assert any(f.rule_id == "SECRET_GENERIC_PASSWORD" for f in findings)


def test_allowlist_suppresses_placeholders():
    findings = scan_text("f.yaml", 'password: "changeme"')
    assert findings == []


def test_low_entropy_generic_is_ignored():
    # Meets length but is low-entropy / repetitive -> gated out.
    findings = scan_text("f.yaml", 'password: "aaaaaaaa"')
    assert all(f.rule_id != "SECRET_GENERIC_PASSWORD" for f in findings)


def test_line_numbers_are_reported():
    text = "line1\nline2\napi_key = \"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345\""
    findings = scan_text("f.txt", text)
    assert findings
    assert findings[0].resource.line == 3
