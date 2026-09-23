"""Core data models shared across the whole pipeline.

Everything Warden discovers — a resource in a Terraform file, a policy
violation, a leaked secret, a correlated attack chain — is represented with the
small set of dataclasses defined here. Keeping these decoupled from any parser
or output format is what lets new parsers and new reporters be added without
touching the engine.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Severity(enum.IntEnum):
    """Ordered severity levels.

    Implemented as an ``IntEnum`` so findings sort naturally (CRITICAL first)
    and thresholds can be compared with plain ``>=``.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:  # pragma: no cover - defensive
            raise ValueError(f"Unknown severity: {value!r}") from exc

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


class ResourceKind(str, enum.Enum):
    """The IaC ecosystem a resource comes from."""

    TERRAFORM = "terraform"
    DOCKERFILE = "dockerfile"
    KUBERNETES = "kubernetes"


@dataclass
class Resource:
    """A single analysable unit extracted from an IaC file.

    A Terraform ``aws_s3_bucket`` block, a Kubernetes ``Deployment`` or a whole
    Dockerfile all become a ``Resource``. ``attributes`` is a normalised,
    nested dict of the resource's configuration that rules query with dotted
    paths (see :func:`warden.engine.get_path`).
    """

    kind: ResourceKind
    resource_type: str
    name: str
    file_path: str
    line: int = 1
    attributes: dict[str, Any] = field(default_factory=dict)
    # Free-form tags a parser can attach to help correlation
    # (e.g. {"public": True} once a rule proves the resource is internet-facing).
    labels: set[str] = field(default_factory=set)

    @property
    def address(self) -> str:
        """A stable, human-readable identifier, e.g. ``aws_s3_bucket.logs``."""
        return f"{self.resource_type}.{self.name}"


@dataclass
class Finding:
    """A single policy violation or detected issue tied to a resource."""

    rule_id: str
    title: str
    severity: Severity
    resource: Resource
    message: str
    remediation: str = ""
    # Semantic tags used by the correlation engine, e.g. {"public-exposure"}.
    tags: set[str] = field(default_factory=set)

    @property
    def location(self) -> str:
        return f"{self.resource.file_path}:{self.resource.line}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.name,
            "resource": self.resource.address,
            "resource_type": self.resource.resource_type,
            "file": self.resource.file_path,
            "line": self.resource.line,
            "message": self.message,
            "remediation": self.remediation,
            "tags": sorted(self.tags),
        }


@dataclass
class AttackChain:
    """A correlated group of findings that together enable a real attack path.

    This is Warden's differentiator: a public S3 bucket is a MEDIUM on its own,
    but *public bucket + no encryption + wildcard IAM policy* is a data-breach
    waiting to happen. A chain scores higher than the sum of its parts.
    """

    chain_id: str
    title: str
    narrative: str
    findings: list[Finding]
    score: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "title": self.title,
            "narrative": self.narrative,
            "score": round(self.score, 1),
            "findings": [f.rule_id for f in self.findings],
        }


@dataclass
class ScanResult:
    """The complete output of a scan: resources, findings and attack chains."""

    resources: list[Resource] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    chains: list[AttackChain] = field(default_factory=list)

    def counts_by_severity(self) -> dict[str, int]:
        counts = {s.name: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.name] += 1
        return counts

    def highest_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max(f.severity for f in self.findings)
