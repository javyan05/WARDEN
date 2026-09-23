"""Tests for the attack-chain correlation engine."""

from warden.correlation import correlate
from warden.models import Finding, Resource, ResourceKind, Severity


def _finding(rule_id, tags, severity=Severity.HIGH, resource_name="r"):
    res = Resource(
        kind=ResourceKind.TERRAFORM,
        resource_type="aws_s3_bucket",
        name=resource_name,
        file_path="f.tf",
    )
    return Finding(
        rule_id=rule_id,
        title=rule_id,
        severity=severity,
        resource=res,
        message="m",
        tags=set(tags),
    )


def test_same_resource_chain_requires_one_resource():
    # Public + unencrypted on the SAME bucket -> chain fires.
    findings = [
        _finding("PUB", {"public-exposure", "data-store"}, resource_name="bucket_a"),
        _finding("ENC", {"encryption-at-rest", "data-store"}, resource_name="bucket_a"),
    ]
    chains = correlate(findings)
    assert any(c.chain_id == "CHAIN_PUBLIC_UNENCRYPTED_STORE" for c in chains)


def test_same_resource_chain_not_fired_across_resources():
    # The two issues live on different buckets -> no same-resource chain.
    findings = [
        _finding("PUB", {"public-exposure", "data-store"}, resource_name="bucket_a"),
        _finding("ENC", {"encryption-at-rest", "data-store"}, resource_name="bucket_b"),
    ]
    chains = correlate(findings)
    assert all(c.chain_id != "CHAIN_PUBLIC_UNENCRYPTED_STORE" for c in chains)


def test_global_chain_container_to_cloud_admin():
    findings = [
        _finding("PRIV", {"privilege"}, severity=Severity.CRITICAL),
        _finding("IAM", {"excessive-permissions", "iam"}, severity=Severity.CRITICAL),
    ]
    chains = correlate(findings)
    chain = next(c for c in chains if c.chain_id == "CHAIN_CONTAINER_TO_CLOUD_ADMIN")
    # Score is boosted above the raw severity-weight sum by the multiplier.
    assert chain.score > 9.0


def test_chains_sorted_by_score_desc():
    findings = [
        _finding("PRIV", {"privilege"}, severity=Severity.CRITICAL),
        _finding("IAM", {"excessive-permissions", "iam"}, severity=Severity.CRITICAL),
        _finding("SEC", {"hardcoded-secret"}, severity=Severity.MEDIUM),
        _finding("PUB", {"public-exposure"}, severity=Severity.MEDIUM),
    ]
    chains = correlate(findings)
    scores = [c.score for c in chains]
    assert scores == sorted(scores, reverse=True)


def test_no_chain_when_tags_absent():
    findings = [_finding("SOLO", {"image-size"}, severity=Severity.LOW)]
    assert correlate(findings) == []
