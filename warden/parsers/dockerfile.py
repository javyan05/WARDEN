"""Dockerfile parser.

Dockerfiles are not declarative like Terraform, so instead of many resources we
emit a single :class:`~warden.models.Resource` per Dockerfile whose attributes
summarise the security-relevant facts rules care about: the base image, whether
a non-root ``USER`` is set, exposed ports, and the raw instruction list.
"""

from __future__ import annotations

import os

from warden.models import Resource, ResourceKind


def matches(path: str) -> bool:
    base = os.path.basename(path).lower()
    return base == "dockerfile" or base.startswith("dockerfile.") or base.endswith(".dockerfile")


def _split_instruction(line: str) -> tuple[str, str]:
    parts = line.split(maxsplit=1)
    instruction = parts[0].upper()
    argument = parts[1].strip() if len(parts) > 1 else ""
    return instruction, argument


def parse(path: str) -> list[Resource]:
    with open(path, encoding="utf-8") as handle:
        lines = handle.readlines()

    instructions: list[dict] = []
    base_images: list[str] = []
    exposed_ports: list[str] = []
    final_user: str | None = None
    uses_latest = False
    runs_apt_without_cleanup = False
    adds_remote = False

    for idx, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        instruction, argument = _split_instruction(stripped)
        instructions.append({"instruction": instruction, "argument": argument, "line": idx})

        if instruction == "FROM":
            image = argument.split(" as ")[0].split(" AS ")[0].strip()
            base_images.append(image)
            if ":" not in image or image.endswith(":latest"):
                uses_latest = True
        elif instruction == "USER":
            final_user = argument.strip()
        elif instruction == "EXPOSE":
            exposed_ports.extend(argument.split())
        elif instruction == "RUN":
            low = argument.lower()
            if ("apt-get install" in low or "apt install" in low) and "rm -rf /var/lib/apt" not in low:
                runs_apt_without_cleanup = True
        elif instruction == "ADD":
            if argument.startswith("http://") or argument.startswith("https://"):
                adds_remote = True

    attributes = {
        "base_images": base_images,
        "final_user": final_user,
        "runs_as_root": final_user is None or final_user in ("root", "0"),
        "exposed_ports": exposed_ports,
        "uses_latest_tag": uses_latest,
        "apt_without_cleanup": runs_apt_without_cleanup,
        "adds_remote_url": adds_remote,
        "instructions": instructions,
    }

    name = os.path.basename(os.path.dirname(path)) or "image"
    return [
        Resource(
            kind=ResourceKind.DOCKERFILE,
            resource_type="dockerfile",
            name=name,
            file_path=path,
            line=1,
            attributes=attributes,
        )
    ]
