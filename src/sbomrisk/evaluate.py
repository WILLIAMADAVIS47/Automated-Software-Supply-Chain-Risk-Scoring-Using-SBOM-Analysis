"""Evaluation measures and weight sensitivity analysis (Task I).

Implements Section 8 of the scoring specification: differentiation from the
CVSS-only baseline, justification of entering components, weight stability
(each weight changed by +/-0.05 and +/-0.10, others rescaled, 20 runs per
project) and vulnerability density by depth.
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

from .score import FACTORS, RankedComponent, rank

TOP = 10
DELTAS = (-0.10, -0.05, 0.05, 0.10)
NON_CVSS = {"exploit_probability", "known_exploitation", "depth"}


def kendall_tau(order_a: list[str], order_b: list[str]) -> float:
    """Kendall's tau between two strict rankings of the same items (no ties, so tau-a equals tau-b)."""
    pos = {item: i for i, item in enumerate(order_b)}
    n = len(order_a)
    if n < 2:
        return 1.0
    concordant = discordant = 0
    for i in range(n):
        for j in range(i + 1, n):
            if pos[order_a[i]] < pos[order_a[j]]:
                concordant += 1
            else:
                discordant += 1
    return (concordant - discordant) / (n * (n - 1) / 2)


def varied_weights(weights: dict[str, float], factor: str, delta: float) -> dict[str, float] | None:
    """Change one weight by delta and rescale the others proportionally so the sum stays 1."""
    new = weights[factor] + delta
    if new < 0 or new > 1:
        return None
    rest = 1 - weights[factor]
    scale = (1 - new) / rest if rest else 0
    return {f: (new if f == factor else w * scale) for f, w in weights.items()}


def differentiation(ranked: list[RankedComponent]) -> dict:
    ctx = [r.purl for r in ranked]
    base = [r.purl for r in sorted(ranked, key=lambda r: r.baseline_rank)]
    top_ctx, top_base = set(ctx[:TOP]), set(base[:TOP])
    entering = [r for r in ranked[:TOP] if r.purl not in top_base]
    justified = [r for r in entering if NON_CVSS & set(r.top_factors)]
    return {
        "ranked": len(ranked),
        "top10_new_entries": len(top_ctx - top_base),
        "top10_meaningful": len(ranked) > TOP,
        "kendall_tau": round(kendall_tau(ctx, base), 4),
        "entering": [{"component": r.label, "rank": r.rank, "baseline_rank": r.baseline_rank,
                      "top_factors": r.top_factors, "justified": r in justified} for r in entering],
        "all_entering_justified": len(justified) == len(entering),
        "rank_changes": sum(r.rank != r.baseline_rank for r in ranked),
    }


def sensitivity(enrichment: dict, weights: dict[str, float], default: list[RankedComponent],
                max_depth: int | None = None) -> list[dict]:
    default_order = [r.purl for r in default]
    default_top = set(default_order[:TOP])
    runs = []
    for factor in FACTORS:
        for delta in DELTAS:
            w = varied_weights(weights, factor, delta)
            if w is None:
                continue
            order = [r.purl for r in rank(enrichment, w, max_depth)]
            overlap = len(set(order[:TOP]) & default_top)
            tau = kendall_tau(order, default_order)
            runs.append({"factor": factor, "delta": delta, "weights": {k: round(v, 4) for k, v in w.items()},
                         "top10_overlap": overlap, "kendall_tau": round(tau, 4),
                         "stable": overlap >= min(8, len(default_top)) and tau >= 0.80})
    return runs


def density(ranked: list[RankedComponent], total_components: int | None = None) -> dict:
    by_depth = Counter(r.depth if r.depth is not None else "unreachable" for r in ranked)
    total = sum(r.score for r in ranked)
    direct = sum(r.score for r in ranked if r.depth == 1)
    return {"vulnerable_by_depth": {str(k): v for k, v in sorted(by_depth.items(), key=lambda kv: str(kv[0]))},
            "direct_share_of_risk": round(direct / total, 4) if total else 0.0,
            "direct_share_of_components": round(by_depth.get(1, 0) / len(ranked), 4) if ranked else 0.0}


def evaluate_project(name: str, enrichment: dict, weights: dict[str, float], max_depth: int | None = None) -> dict:
    ranked = rank(enrichment, weights, max_depth)
    runs = sensitivity(enrichment, weights, ranked, max_depth)
    stable = sum(r["stable"] for r in runs)
    flags = Counter()
    for r in ranked:
        for fl in r.flags:
            flags[fl.split(": ", 1)[-1].split("; depth treated as")[0]] += 1
    return {
        "project": name,
        "analysis_date": enrichment["run"]["analysis_date"],
        "components": enrichment["summary"]["components"],
        "vulnerabilities": enrichment["summary"]["vulnerabilities"],
        "differentiation": differentiation(ranked),
        "sensitivity": {"runs": len(runs), "stable_runs": stable,
                        "stable_share": round(stable / len(runs), 4) if runs else 1.0,
                        "min_top10_overlap": min((r["top10_overlap"] for r in runs), default=None),
                        "min_kendall_tau": min((r["kendall_tau"] for r in runs), default=None),
                        "detail": runs},
        "density": density(ranked),
        "flags": dict(flags),
        "not_assessed": enrichment["summary"].get("not_assessed", 0),
    }


def overall(projects: list[dict]) -> dict:
    """Pass/fail against the D1 targets."""
    meaningful = [p for p in projects if p["differentiation"]["top10_meaningful"]]
    diff_pass = [p["project"] for p in meaningful if p["differentiation"]["top10_new_entries"] >= 3]
    return {
        "differentiation_target": "at least 3 of 10 different in at least 3 of the 4 projects",
        "differentiation_met_in": diff_pass,
        "differentiation_met": len(diff_pass) >= 3,
        "justification_met": all(p["differentiation"]["all_entering_justified"] for p in projects),
        "stability_target": "top-ten overlap >= 8 and Kendall tau >= 0.80 in 90 percent of runs",
        "stability_met": all(p["sensitivity"]["stable_share"] >= 0.90 for p in projects),
    }


def write_outputs(out_dir: Path, result: dict) -> None:
    """evaluation.json plus summary.csv, sensitivity.csv and density.csv for Excel."""
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "evaluation.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    with open(out_dir / "summary.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["project", "analysis_date", "components", "vulnerable_ranked", "vulnerabilities",
                    "top10_new_entries", "kendall_tau", "rank_changes", "entering_justified",
                    "stable_runs", "runs", "min_top10_overlap", "min_kendall_tau", "direct_share_of_risk"])
        for p in result["projects"]:
            d, s = p["differentiation"], p["sensitivity"]
            w.writerow([p["project"], p["analysis_date"], p["components"], d["ranked"], p["vulnerabilities"],
                        d["top10_new_entries"] if d["top10_meaningful"] else "n/a", d["kendall_tau"],
                        d["rank_changes"], d["all_entering_justified"], s["stable_runs"], s["runs"],
                        s["min_top10_overlap"], s["min_kendall_tau"], p["density"]["direct_share_of_risk"]])
    with open(out_dir / "sensitivity.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["project", "factor", "delta", *FACTORS, "top10_overlap", "kendall_tau", "stable"])
        for p in result["projects"]:
            for r in p["sensitivity"]["detail"]:
                w.writerow([p["project"], r["factor"], r["delta"], *[r["weights"][x] for x in FACTORS],
                            r["top10_overlap"], r["kendall_tau"], r["stable"]])
    with open(out_dir / "density.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["project", "depth", "vulnerable_components"])
        for p in result["projects"]:
            for depth, n in p["density"]["vulnerable_by_depth"].items():
                w.writerow([p["project"], depth, n])
