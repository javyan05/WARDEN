"""Parsers turn raw IaC files into normalised :class:`~warden.models.Resource`s.

Each parser exposes:

* ``EXTENSIONS`` / ``FILENAMES`` — how the dispatcher decides it applies.
* ``parse(path) -> list[Resource]`` — the actual work.

Adding support for a new IaC format is just adding a module here and
registering it in :data:`PARSERS`; nothing else in Warden needs to change.
"""

from __future__ import annotations

import os
from typing import Callable

from warden.models import Resource

from . import dockerfile, kubernetes, terraform

# Ordered list of (predicate, parse_fn). The first matching predicate wins.
PARSERS: list[tuple[Callable[[str], bool], Callable[[str], list[Resource]]]] = [
    (terraform.matches, terraform.parse),
    (dockerfile.matches, dockerfile.parse),
    (kubernetes.matches, kubernetes.parse),
]


def parse_file(path: str) -> list[Resource]:
    """Parse a single file with whichever parser claims it. Empty if none do."""
    for predicate, parse_fn in PARSERS:
        if predicate(path):
            try:
                return parse_fn(path)
            except Exception:  # pragma: no cover - a broken file shouldn't abort a scan
                return []
    return []


def discover(root: str) -> list[str]:
    """Recursively list files under ``root`` that some parser can handle."""
    if os.path.isfile(root):
        return [root] if any(pred(root) for pred, _ in PARSERS) else []

    found: list[str] = []
    skip_dirs = {".git", ".terraform", "node_modules", ".venv", "__pycache__"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for filename in filenames:
            full = os.path.join(dirpath, filename)
            if any(pred(full) for pred, _ in PARSERS):
                found.append(full)
    return sorted(found)
