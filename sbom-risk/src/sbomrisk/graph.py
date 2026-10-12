"""Dependency graph construction and depth computation (Task F).

Depth is the shortest path length from the root application to a component:
direct dependencies have depth 1. It feeds the Dependency Depth Factor in the
scoring specification ("docs/D1 Scoring Specification.docx", factor D).
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass

from .models import Component
from .parser import ParsedSBOM

SYNTHETIC_ROOT = "__synthetic_root__"


@dataclass
class GraphStats:
    components: int
    edges: int
    direct: int
    max_depth: int
    depth_histogram: dict[int, int]
    unreachable: int
    synthetic_root: bool
    has_cycles: bool


class DependencyGraph:
    def __init__(self, sbom: ParsedSBOM):
        self.sbom = sbom
        self.components: dict[str, Component] = sbom.components
        self.synthetic_root = sbom.root is None
        self.root_ref = SYNTHETIC_ROOT if self.synthetic_root else sbom.root.bom_ref
        self.root_children: set[str] = set()

        for parent, child in sbom.edges:
            if child == self.root_ref:
                continue  # an edge back into the application itself carries no depth information
            if parent == self.root_ref:
                self.root_children.add(child)
            else:
                self.components[parent].children.add(child)
            self.components[child].parents.add(parent)

        if self.synthetic_root:
            # No root in metadata: treat every component nothing else depends on as direct.
            self.root_children = {ref for ref, c in self.components.items() if not c.parents}
            for ref in self.root_children:
                self.components[ref].parents.add(SYNTHETIC_ROOT)

        self.compute_depths()

    def children_of(self, ref: str) -> set[str]:
        return self.root_children if ref == self.root_ref else self.components[ref].children

    def compute_depths(self) -> None:
        """Breadth-first search from the root; cycle-safe because each node is visited once."""
        for comp in self.components.values():
            comp.depth = None
        queue = deque([(self.root_ref, 0)])
        seen = {self.root_ref}
        while queue:
            ref, depth = queue.popleft()
            for child in self.children_of(ref):
                if child in seen:
                    continue
                seen.add(child)
                self.components[child].depth = depth + 1
                queue.append((child, depth + 1))

    def unreachable(self) -> list[Component]:
        return [c for c in self.components.values() if c.depth is None]

    def has_cycles(self) -> bool:
        indegree = {ref: 0 for ref in self.components}
        for comp in self.components.values():
            for child in comp.children:
                indegree[child] += 1
        queue = deque(ref for ref, d in indegree.items() if d == 0)
        visited = 0
        while queue:
            ref = queue.popleft()
            visited += 1
            for child in self.components[ref].children:
                indegree[child] -= 1
                if indegree[child] == 0:
                    queue.append(child)
        return visited != len(self.components)

    def path_to(self, ref: str) -> list[str]:
        """One shortest path root -> ref (bom-refs, root excluded), used in explanations."""
        prev: dict[str, str] = {}
        queue = deque([self.root_ref])
        seen = {self.root_ref}
        while queue:
            cur = queue.popleft()
            if cur == ref:
                break
            for child in self.children_of(cur):
                if child not in seen:
                    seen.add(child)
                    prev[child] = cur
                    queue.append(child)
        if ref not in prev:
            return []
        path = [ref]
        while prev.get(path[-1], self.root_ref) != self.root_ref:
            path.append(prev[path[-1]])
        return list(reversed(path))

    def stats(self) -> GraphStats:
        depths = [c.depth for c in self.components.values() if c.depth is not None]
        hist = dict(sorted(Counter(depths).items()))
        edge_count = len(self.root_children) + sum(len(c.children) for c in self.components.values())
        return GraphStats(
            components=len(self.components),
            edges=edge_count,
            direct=len(self.root_children),
            max_depth=max(depths, default=0),
            depth_histogram=hist,
            unreachable=len(self.unreachable()),
            synthetic_root=self.synthetic_root,
            has_cycles=self.has_cycles(),
        )
