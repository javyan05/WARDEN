"""Terraform (HCL) parser.

Uses ``python-hcl2`` to load ``.tf`` files and flattens every ``resource``
block into a :class:`~warden.models.Resource`. python-hcl2 represents the body
of each resource as a list containing one dict, which we unwrap into plain
nested dicts so rules can query attributes with dotted paths.
"""

from __future__ import annotations

from typing import Any

import hcl2

from warden.models import Resource, ResourceKind

# Metadata keys python-hcl2 (v8+) injects into every block; not real attributes.
_META_KEYS = {"__is_block__", "__comments__", "__start_line__", "__end_line__"}


def matches(path: str) -> bool:
    return path.endswith(".tf")


def _unquote(text: str) -> str:
    """Strip the surrounding quotes / interpolation python-hcl2 v8 preserves.

    v8 returns string tokens verbatim, e.g. ``'"public-read"'`` or
    ``'${var.name}'``. Rules want the logical value, so we peel the wrapping
    quotes and a single ``${...}`` interpolation layer.
    """
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("\"", "'"):
        text = text[1:-1]
    if text.startswith("${") and text.endswith("}"):
        text = text[2:-1]
    return text


def _normalize(value: Any) -> Any:
    """Recursively clean a parsed value: strip quotes, drop block metadata."""
    if isinstance(value, str):
        return _unquote(value)
    if isinstance(value, list):
        return [_normalize(v) for v in value]
    if isinstance(value, dict):
        return {k: _normalize(v) for k, v in value.items() if k not in _META_KEYS}
    return value


def _line_of(raw_text: str, resource_type: str, name: str) -> int:
    """Best-effort line lookup so findings point at the right spot in the file.

    python-hcl2 does not preserve line numbers, so we scan the source for the
    ``resource "<type>" "<name>"`` header. Falls back to line 1.
    """
    needle_a = f'resource "{resource_type}" "{name}"'
    needle_b = f"resource \"{resource_type}\" \"{name}\""
    for i, line in enumerate(raw_text.splitlines(), start=1):
        if needle_a in line or needle_b in line:
            return i
    return 1


def parse(path: str) -> list[Resource]:
    with open(path, encoding="utf-8") as handle:
        raw_text = handle.read()

    parsed = hcl2.loads(raw_text)
    resources: list[Resource] = []

    for block in parsed.get("resource", []):
        if not isinstance(block, dict):
            continue
        # Each block is {resource_type: {name: {..attributes..}}}
        for resource_type, named in block.items():
            resource_type = _unquote(resource_type)
            if not isinstance(named, dict):
                continue
            for name, attributes in named.items():
                name = _unquote(name)
                # python-hcl2 sometimes wraps the body in a single-element list.
                if isinstance(attributes, list) and attributes:
                    attributes = attributes[0]
                if not isinstance(attributes, dict):
                    attributes = {}
                resources.append(
                    Resource(
                        kind=ResourceKind.TERRAFORM,
                        resource_type=resource_type,
                        name=name,
                        file_path=path,
                        line=_line_of(raw_text, resource_type, name),
                        attributes=_normalize(attributes),
                    )
                )
    return resources
