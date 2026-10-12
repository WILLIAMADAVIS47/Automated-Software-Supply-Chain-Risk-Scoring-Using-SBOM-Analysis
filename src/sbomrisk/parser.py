"""CycloneDX JSON SBOM parser (Task F).

Reads a CycloneDX 1.4-1.6 JSON document and returns the root component, a flat
list of components (nested `components` arrays are flattened), and the
dependency edges from the `dependencies` section. SPDX is out of scope (see
proposal Section I.G).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Component, Purl

SUPPORTED_SPEC_VERSIONS = {"1.4", "1.5", "1.6"}


class SBOMError(ValueError):
    """Raised when a document is not a usable CycloneDX JSON SBOM."""


@dataclass
class ParsedSBOM:
    source: str
    spec_version: str
    root: Component | None
    components: dict[str, Component]
    edges: list[tuple[str, str]]  # (parent bom-ref, child bom-ref)
    warnings: list[str] = field(default_factory=list)


def _component_from_json(obj: dict[str, Any], warnings: list[str]) -> Component:
    name = obj.get("name")
    if not name:
        raise SBOMError(f"component without a name: {obj.get('bom-ref')!r}")
    purl = None
    if obj.get("purl"):
        try:
            purl = Purl.parse(obj["purl"])
        except ValueError as exc:
            warnings.append(str(exc))
    bom_ref = obj.get("bom-ref") or obj.get("purl") or f"{obj.get('group') or ''}/{name}@{obj.get('version') or ''}"
    return Component(
        bom_ref=bom_ref,
        name=name,
        version=obj.get("version"),
        type=obj.get("type", "library"),
        group=obj.get("group"),
        purl=purl,
        purl_string=obj.get("purl"),
        scope=obj.get("scope"),
    )


def _flatten(objs: list[dict[str, Any]]):
    for obj in objs:
        yield obj
        yield from _flatten(obj.get("components", []))


def parse_document(doc: dict[str, Any], source: str = "<memory>") -> ParsedSBOM:
    if doc.get("bomFormat") != "CycloneDX":
        raise SBOMError(f"{source}: bomFormat is {doc.get('bomFormat')!r}, expected 'CycloneDX'")
    spec = str(doc.get("specVersion", ""))
    if spec not in SUPPORTED_SPEC_VERSIONS:
        raise SBOMError(f"{source}: unsupported CycloneDX specVersion {spec!r}")

    warnings: list[str] = []
    root_obj = (doc.get("metadata") or {}).get("component")
    root = _component_from_json(root_obj, warnings) if root_obj else None

    components: dict[str, Component] = {}
    for obj in _flatten(doc.get("components", [])):
        comp = _component_from_json(obj, warnings)
        if root and comp.bom_ref == root.bom_ref:
            continue
        if comp.bom_ref in components:
            warnings.append(f"duplicate bom-ref {comp.bom_ref!r}; keeping first occurrence")
            continue
        components[comp.bom_ref] = comp

    known = set(components) | ({root.bom_ref} if root else set())
    edges: list[tuple[str, str]] = []
    for dep in doc.get("dependencies", []):
        parent = dep.get("ref")
        for child in dep.get("dependsOn", []):
            if parent not in known or child not in known:
                warnings.append(f"dependency edge references unknown bom-ref: {parent!r} -> {child!r}")
                continue
            if parent != child:
                edges.append((parent, child))

    return ParsedSBOM(source, spec, root, components, edges, warnings)


def parse_file(path: str | Path) -> ParsedSBOM:
    path = Path(path)
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SBOMError(f"{path}: not valid JSON ({exc})") from exc
    return parse_document(doc, source=str(path))
