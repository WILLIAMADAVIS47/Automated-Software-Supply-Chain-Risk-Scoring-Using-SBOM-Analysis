"""Command-line entry point: `sbomrisk inspect` and `sbomrisk graph`."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter

from .graph import DependencyGraph
from .parser import SBOMError, parse_file


def _load(path: str) -> DependencyGraph:
    return DependencyGraph(parse_file(path))


def cmd_inspect(args: argparse.Namespace) -> int:
    for path in args.sbom:
        graph = _load(path)
        sbom, st = graph.sbom, graph.stats()
        root = sbom.root.display_name if sbom.root else "(none in metadata; synthetic root used)"
        ecosystems = Counter(c.ecosystem or "unknown" for c in graph.components.values())
        print(f"{path}")
        print(f"  CycloneDX {sbom.spec_version}  root: {root}")
        print(f"  components: {st.components}  edges: {st.edges}  direct: {st.direct}  max depth: {st.max_depth}")
        print(f"  depth histogram: {st.depth_histogram}")
        print(f"  ecosystems: {dict(ecosystems)}")
        print(f"  unreachable: {st.unreachable}  cycles: {'yes' if st.has_cycles else 'no'}  warnings: {len(sbom.warnings)}")
        if args.verbose:
            for w in sbom.warnings:
                print(f"    warning: {w}")
    return 0


def cmd_graph(args: argparse.Namespace) -> int:
    graph = _load(args.sbom)
    rows = [
        {
            "bom_ref": c.bom_ref,
            "name": c.purl.coordinate if c.purl else c.name,
            "version": c.version or "",
            "ecosystem": c.ecosystem or "",
            "purl": c.purl_string or "",
            "depth": c.depth if c.depth is not None else "",
            "fan_in": len(c.parents),
            "fan_out": len(c.children),
        }
        for c in sorted(graph.components.values(), key=lambda c: (c.depth or 10**6, c.display_name))
    ]
    out = open(args.output, "w", newline="", encoding="utf-8") if args.output else sys.stdout
    try:
        if args.format == "json":
            json.dump(rows, out, indent=2)
            out.write("\n")
        else:
            writer = csv.DictWriter(out, fieldnames=list(rows[0]) if rows else ["bom_ref"])
            writer.writeheader()
            writer.writerows(rows)
    finally:
        if out is not sys.stdout:
            out.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sbomrisk", description="SBOM supply chain risk scoring")
    sub = parser.add_subparsers(dest="command", required=True)

    p_inspect = sub.add_parser("inspect", help="summarize one or more CycloneDX JSON SBOMs")
    p_inspect.add_argument("sbom", nargs="+")
    p_inspect.add_argument("-v", "--verbose", action="store_true")
    p_inspect.set_defaults(func=cmd_inspect)

    p_graph = sub.add_parser("graph", help="export components with dependency depth and fan-in/out")
    p_graph.add_argument("sbom")
    p_graph.add_argument("-f", "--format", choices=["csv", "json"], default="csv")
    p_graph.add_argument("-o", "--output")
    p_graph.set_defaults(func=cmd_graph)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except SBOMError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
