"""Core data types shared across the pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import unquote


@dataclass(frozen=True)
class Purl:
    """Minimal Package URL (purl) representation: pkg:type/namespace/name@version?qualifiers."""

    type: str
    namespace: str | None
    name: str
    version: str | None

    @classmethod
    def parse(cls, purl: str) -> "Purl":
        if not purl.startswith("pkg:"):
            raise ValueError(f"not a purl: {purl!r}")
        rest = purl[4:].split("#", 1)[0].split("?", 1)[0]
        version = None
        if "@" in rest:
            rest, version = rest.rsplit("@", 1)
            version = unquote(version)
        ptype, _, path = rest.partition("/")
        parts = [unquote(p) for p in path.split("/") if p]
        if not parts:
            raise ValueError(f"purl has no name: {purl!r}")
        namespace = "/".join(parts[:-1]) or None
        return cls(ptype.lower(), namespace, parts[-1], version)

    @property
    def coordinate(self) -> str:
        """Ecosystem-native package name, e.g. '@babel/core', 'org.yaml:snakeyaml', 'golang.org/x/net'."""
        if self.namespace is None:
            return self.name
        sep = ":" if self.type == "maven" else "/"
        return f"{self.namespace}{sep}{self.name}"


# purl type -> OSV ecosystem name (used by enrichment, Task G)
OSV_ECOSYSTEMS = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "golang": "Go",
    "nuget": "NuGet",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "composer": "Packagist",
}


@dataclass
class Component:
    bom_ref: str
    name: str
    version: str | None
    type: str = "library"
    group: str | None = None
    purl: Purl | None = None
    purl_string: str | None = None
    scope: str | None = None
    # Filled in by DependencyGraph.compute_depths(); 1 = direct dependency of the root.
    depth: int | None = None
    parents: set[str] = field(default_factory=set)
    children: set[str] = field(default_factory=set)

    @property
    def ecosystem(self) -> str | None:
        return self.purl.type if self.purl else None

    @property
    def osv_ecosystem(self) -> str | None:
        return OSV_ECOSYSTEMS.get(self.ecosystem or "")

    @property
    def display_name(self) -> str:
        base = self.purl.coordinate if self.purl else (f"{self.group}/{self.name}" if self.group else self.name)
        return f"{base}@{self.version}" if self.version else base
