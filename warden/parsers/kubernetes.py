"""Kubernetes manifest parser.

Loads multi-document YAML files and turns each object with a ``kind`` into a
:class:`~warden.models.Resource`. For workloads (Deployment, Pod, DaemonSet,
StatefulSet, Job…) it hoists the pod ``securityContext`` and container
security settings to the top level of ``attributes`` so rules stay simple.
"""

from __future__ import annotations

import yaml

from warden.models import Resource, ResourceKind

_WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "Pod"}


def matches(path: str) -> bool:
    if not (path.endswith(".yaml") or path.endswith(".yml")):
        return False
    # Cheap sniff so we don't claim every YAML file in the repo.
    try:
        with open(path, encoding="utf-8") as handle:
            head = handle.read(4096)
    except OSError:
        return False
    return "apiVersion" in head and "kind" in head


def _pod_spec(doc: dict) -> dict:
    """Return the PodSpec regardless of the workload kind wrapping it."""
    if doc.get("kind") == "Pod":
        return doc.get("spec", {}) or {}
    if doc.get("kind") == "CronJob":
        return (
            doc.get("spec", {})
            .get("jobTemplate", {})
            .get("spec", {})
            .get("template", {})
            .get("spec", {})
            or {}
        )
    return doc.get("spec", {}).get("template", {}).get("spec", {}) or {}


def parse(path: str) -> list[Resource]:
    with open(path, encoding="utf-8") as handle:
        documents = list(yaml.safe_load_all(handle))

    resources: list[Resource] = []
    for doc in documents:
        if not isinstance(doc, dict) or "kind" not in doc:
            continue

        kind = doc.get("kind", "Unknown")
        metadata = doc.get("metadata", {}) or {}
        name = metadata.get("name", "unnamed")
        attributes = dict(doc)

        if kind in _WORKLOAD_KINDS:
            pod_spec = _pod_spec(doc)
            containers = pod_spec.get("containers", []) or []
            attributes["pod_security_context"] = pod_spec.get("securityContext", {}) or {}
            attributes["host_network"] = pod_spec.get("hostNetwork", False)
            attributes["host_pid"] = pod_spec.get("hostPID", False)
            attributes["containers"] = containers
            attributes["privileged_containers"] = [
                c.get("name", "?")
                for c in containers
                if (c.get("securityContext", {}) or {}).get("privileged") is True
            ]
            attributes["root_containers"] = [
                c.get("name", "?")
                for c in containers
                if (c.get("securityContext", {}) or {}).get("runAsNonRoot") is not True
            ]

        resources.append(
            Resource(
                kind=ResourceKind.KUBERNETES,
                resource_type=kind,
                name=name,
                file_path=path,
                line=1,
                attributes=attributes,
            )
        )
    return resources
