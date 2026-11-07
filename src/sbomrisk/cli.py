"""Command-line entry point: `sbomrisk inspect`, `graph`, `enrich`, `rank` and `evaluate`."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

from . import enrich as enrichment
from . import evaluate as evaluation
from . import score as scoring
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


def cmd_enrich(args: argparse.Namespace) -> int:
    problem = enrichment.nvd_key_problem(enrichment.default_nvd_key())
    if problem:
        print(f"error: {problem}. Set the real key with $env:NVD_API_KEY=\"...\" or clear it with "
              f"Remove-Item Env:NVD_API_KEY", file=sys.stderr)
        return 5
    graph = _load(args.sbom)
    fetcher = enrichment.Fetcher(args.cache_dir, offline=args.offline, nvd_api_key=enrichment.default_nvd_key())
    stem = Path(args.sbom).name.removesuffix(".json").removesuffix(".cdx")
    analysis_date = args.date or enrichment.date.today().isoformat()
    out_path = Path(args.output) if args.output else Path("results") / f"{stem}-{analysis_date}" / "enrichment.json"
    print(f"{args.sbom}")
    try:
        result = enrichment.enrich(graph, fetcher, analysis_date, progress=lambda m: print(f"  ... {m}", flush=True))
    except enrichment.OfflineMiss as exc:
        print(f"error: --offline was given but this response is not cached: {exc}", file=sys.stderr)
        return 3
    except enrichment.NVDUnavailable as exc:
        print(f"error: {exc}, so the NVD API key was probably rejected. Nothing was written. Delete the folder "
              f"{Path(args.cache_dir) / 'services.nvd.nist.gov'}, check the key, and run the command again.", file=sys.stderr)
        return 5
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    enrichment.print_summary(result)
    print(f"  written to {out_path}")
    return 0


def _stem(sbom: str) -> str:
    return Path(sbom).name.removesuffix(".json").removesuffix(".cdx")


def _find_enrichment(sbom: str, given: str | None) -> Path | None:
    """The given enrichment file, or the most recent results/<sbom>-<date>/enrichment.json."""
    if given:
        return Path(given)
    found = sorted(Path("results").glob(f"{_stem(sbom)}-*/enrichment.json"))
    return found[-1] if found else None


def _weights(path: str | None) -> dict[str, float]:
    return scoring.load_weights(Path(path).read_text(encoding="utf-8")) if path else scoring.default_weights()


def _missing(sbom: str) -> int:
    print(f"error: no enrichment results for {sbom}; run `sbomrisk enrich {sbom}` first", file=sys.stderr)
    return 4


def cmd_rank(args: argparse.Namespace) -> int:
    graph = _load(args.sbom)
    source = _find_enrichment(args.sbom, args.enrichment)
    if source is None:
        return _missing(args.sbom)
    enrichment_result = json.loads(source.read_text(encoding="utf-8"))
    weights = _weights(args.weights)
    ranked = scoring.rank(enrichment_result, weights, graph.stats().max_depth)
    out_dir = Path(args.output) if args.output else source.parent
    scoring.write_outputs(out_dir, enrichment_result, ranked, weights,
                          {"enrichment": str(source), "cache_dir": str(Path(args.cache_dir).resolve())})
    print(f"{args.sbom}  (analysis date {enrichment_result['run']['analysis_date']})")
    print(f"  ranked {len(ranked)} vulnerable components; top {min(args.top, len(ranked))}:")
    for r in ranked[:args.top]:
        print(f"  {r.explanation}")
    print(f"  written to {out_dir}")
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    sboms = args.sbom or sorted(str(p) for p in Path("data/sboms").glob("*.cdx.json"))
    weights = _weights(args.weights)
    projects = []
    for sbom in sboms:
        source = _find_enrichment(sbom, None)
        if source is None:
            return _missing(sbom)
        enrichment_result = json.loads(source.read_text(encoding="utf-8"))
        projects.append(evaluation.evaluate_project(_stem(sbom), enrichment_result, weights,
                                                    _load(sbom).stats().max_depth))
    result = {"weights": weights, "projects": projects, "overall": evaluation.overall(projects)}
    out_dir = Path(args.output) if args.output else Path("results") / f"evaluation-{enrichment.date.today().isoformat()}"
    evaluation.write_outputs(out_dir, result)
    print(f"{'project':<24}{'ranked':>7}{'new in top 10':>15}{'Kendall tau':>13}{'stable runs':>13}{'direct risk':>13}")
    for p in projects:
        d, s = p["differentiation"], p["sensitivity"]
        new = str(d["top10_new_entries"]) if d["top10_meaningful"] else "n/a"
        print(f"{p['project']:<24}{d['ranked']:>7}{new:>15}{d['kendall_tau']:>13.2f}"
              f"{s['stable_runs']:>8}/{s['runs']:<4}{p['density']['direct_share_of_risk'] * 100:>12.0f}%")
    o = result["overall"]
    print(f"  differentiation target met: {'yes' if o['differentiation_met'] else 'no'} "
          f"({', '.join(o['differentiation_met_in']) or 'none'})")
    print(f"  every entering component justified by E, X or D: {'yes' if o['justification_met'] else 'no'}")
    print(f"  weight stability target met: {'yes' if o['stability_met'] else 'no'}")
    print(f"  written to {out_dir}")
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

    p_enrich = sub.add_parser("enrich", help="look up vulnerabilities, CVSS, EPSS and KEV status for each component")
    p_enrich.add_argument("sbom")
    p_enrich.add_argument("-o", "--output", help="output JSON (default results/<sbom>-<date>/enrichment.json)")
    p_enrich.add_argument("--date", help="analysis date YYYY-MM-DD (default today)")
    p_enrich.add_argument("--cache-dir", default="cache", help="where API responses are cached (default ./cache)")
    p_enrich.add_argument("--offline", action="store_true", help="use only cached responses")
    p_enrich.set_defaults(func=cmd_enrich)

    p_rank = sub.add_parser("rank", help="score and rank vulnerable components, with the CVSS-only baseline")
    p_rank.add_argument("sbom")
    p_rank.add_argument("--enrichment", help="enrichment.json to use (default: newest in results/<sbom>-<date>)")
    p_rank.add_argument("--weights", help="weights JSON file (default: the D1 weights)")
    p_rank.add_argument("-o", "--output", help="output folder (default: the enrichment's folder)")
    p_rank.add_argument("--top", type=int, default=10, help="how many explanations to print (default 10)")
    p_rank.add_argument("--cache-dir", default="cache", help=argparse.SUPPRESS)
    p_rank.set_defaults(func=cmd_rank)

    p_eval = sub.add_parser("evaluate", help="compare against the baseline and test weight stability (D3)")
    p_eval.add_argument("sbom", nargs="*", help="SBOMs to evaluate (default: every data/sboms/*.cdx.json)")
    p_eval.add_argument("--weights", help="weights JSON file (default: the D1 weights)")
    p_eval.add_argument("-o", "--output", help="output folder (default results/evaluation-<date>)")
    p_eval.set_defaults(func=cmd_evaluate)

    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")  # keep the arrows in explanations from failing on old consoles
    try:
        return args.func(args)
    except SBOMError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
