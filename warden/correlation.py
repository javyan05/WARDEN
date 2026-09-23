"""Correlation engine — Warden's signature feature.

Most scanners hand you a flat list of findings and leave prioritisation to you.
Warden goes further: it looks for *combinations* of findings that together form
a realistic attack path and surfaces them as :class:`~warden.models.AttackChain`
objects scored higher than the individual findings.

The intuition: a public S3 bucket is a HIGH, and "no encryption" is a MEDIUM,
but *the same bucket being public AND unencrypted* is a data-breach primitive
that a reviewer should look at before either issue in isolation. A privileged
container is bad; a privileged container in a stack that also has a wildcard IAM
policy is a full cloud-account-takeover path.

Chains are defined declaratively as tag requirements, so adding a new attack
pattern is a few lines of data, not new control flow.
"""

from __future__ import annotations

from dataclasses import dataclass

from warden.models import AttackChain, Finding, Severity

# Weight applied per finding severity when scoring a chain.
_SEVERITY_WEIGHT = {
    Severity.INFO: 0.5,
    Severity.LOW: 1.0,
    Severity.MEDIUM: 2.5,
    Severity.HIGH: 5.0,
    Severity.CRITICAL: 9.0,
}


@dataclass
class ChainTemplate:
    """A declarative attack-path pattern.

    ``required_tags`` are groups; the chain fires when *every* group is matched
    by at least one finding. ``same_resource`` requires all matched findings to
    live on one resource (e.g. one bucket that is both public and unencrypted).
    ``multiplier`` boosts the combined score to reflect that the whole is more
    dangerous than the parts.
    """

    chain_id: str
    title: str
    narrative: str
    required_tags: list[set[str]]
    multiplier: float
    same_resource: bool = False


def _finding_matches(finding: Finding, tags: set[str]) -> bool:
    return tags.issubset(finding.tags)


# The built-in attack-path library. Ordered by descending impact.
TEMPLATES: list[ChainTemplate] = [
    ChainTemplate(
        chain_id="CHAIN_PUBLIC_UNENCRYPTED_STORE",
        title="Internet-exposed, unencrypted data store",
        narrative=(
            "A data store is reachable from the public internet AND stores its "
            "data unencrypted. An attacker who reaches it — or simply finds it "
            "misconfigured — walks away with cleartext data. Fix the exposure "
            "and enable encryption at rest together."
        ),
        required_tags=[{"public-exposure", "data-store"}, {"encryption-at-rest", "data-store"}],
        multiplier=1.8,
        same_resource=True,
    ),
    ChainTemplate(
        chain_id="CHAIN_CONTAINER_TO_CLOUD_ADMIN",
        title="Container breakout to cloud-admin takeover",
        narrative=(
            "The stack runs an over-privileged container (root or privileged) "
            "AND grants wildcard IAM permissions. A single RCE in that container "
            "escalates to full control of the cloud account via the wildcard "
            "policy. Drop the container privileges and scope the IAM policy."
        ),
        required_tags=[{"privilege"}, {"excessive-permissions", "iam"}],
        multiplier=2.0,
    ),
    ChainTemplate(
        chain_id="CHAIN_SECRET_ON_PUBLIC_SURFACE",
        title="Hardcoded secret next to an internet-facing surface",
        narrative=(
            "A credential is hardcoded in the same codebase that also exposes a "
            "service to the internet. If the secret grants access to that or a "
            "connected service, the exposed surface becomes a direct path in. "
            "Rotate the secret and lock down the exposure."
        ),
        required_tags=[{"hardcoded-secret"}, {"public-exposure"}],
        multiplier=1.6,
    ),
    ChainTemplate(
        chain_id="CHAIN_OPEN_INGRESS_OVERPRIVILEGED",
        title="Open ingress in front of over-privileged IAM",
        narrative=(
            "A security group accepts traffic from 0.0.0.0/0 in an environment "
            "that also hands out wildcard IAM permissions. The open door and the "
            "master key exist in the same blueprint. Restrict ingress and scope "
            "the policy."
        ),
        required_tags=[{"public-exposure", "network"}, {"excessive-permissions", "iam"}],
        multiplier=1.7,
    ),
]


def _base_score(findings: list[Finding]) -> float:
    return sum(_SEVERITY_WEIGHT[f.severity] for f in findings)


def correlate(
    findings: list[Finding], templates: list[ChainTemplate] | None = None
) -> list[AttackChain]:
    """Build attack chains from a flat list of findings."""
    templates = templates or TEMPLATES
    chains: list[AttackChain] = []

    for template in templates:
        if template.same_resource:
            chain = _match_same_resource(template, findings)
        else:
            chain = _match_global(template, findings)
        if chain is not None:
            chains.append(chain)

    # Highest-scoring chains first.
    chains.sort(key=lambda c: c.score, reverse=True)
    return chains


def _build_chain(template: ChainTemplate, matched: list[Finding]) -> AttackChain:
    # De-duplicate while preserving order.
    unique: list[Finding] = []
    seen = set()
    for finding in matched:
        key = (finding.rule_id, finding.location)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    score = _base_score(unique) * template.multiplier
    return AttackChain(
        chain_id=template.chain_id,
        title=template.title,
        narrative=template.narrative,
        findings=unique,
        score=score,
    )


def _match_global(template: ChainTemplate, findings: list[Finding]) -> AttackChain | None:
    matched: list[Finding] = []
    for tag_group in template.required_tags:
        hit = next((f for f in findings if _finding_matches(f, tag_group)), None)
        if hit is None:
            return None
        matched.append(hit)
    return _build_chain(template, matched)


def _match_same_resource(template: ChainTemplate, findings: list[Finding]) -> AttackChain | None:
    # Group findings by resource address, then require all tag groups on one resource.
    by_resource: dict[str, list[Finding]] = {}
    for finding in findings:
        by_resource.setdefault(finding.resource.address, []).append(finding)

    best: AttackChain | None = None
    for resource_findings in by_resource.values():
        matched: list[Finding] = []
        ok = True
        for tag_group in template.required_tags:
            hit = next((f for f in resource_findings if _finding_matches(f, tag_group)), None)
            if hit is None:
                ok = False
                break
            matched.append(hit)
        if ok:
            candidate = _build_chain(template, matched)
            if best is None or candidate.score > best.score:
                best = candidate
    return best
