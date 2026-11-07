"""Contextual risk scoring, ranking, explanations and the CVSS-only baseline (Task H).

Implements Sections 3 to 7 of the scoring specification ("docs/D1 Scoring
Specification.docx") on top of an enrichment result from `enrich.py`:

    VulnScore(v) = w1*S(v) + w2*E(v) + w3*X(v)
    Risk(c)      = max over v in c of VulnScore(v) + w4*D(c) + w5*A(c)

Every factor lies in 0..1 and the weights sum to 1, so Risk(c) does too;
reports show it multiplied by 100.
"""

from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass, field
from datetime import date
from importlib import resources
from pathlib import Path

FACTORS = ("severity", "exploit_probability", "known_exploitation", "depth", "age")
SHORT = {"severity": "S", "exploit_probability": "E", "known_exploitation": "X", "depth": "D", "age": "A"}
AGE_CAP_DAYS = 1826  # five years


def default_weights() -> dict[str, float]:
    return load_weights(resources.files("sbomrisk").joinpath("weights.json").read_text(encoding="utf-8"))


def load_weights(text: str) -> dict[str, float]:
    raw = json.loads(text)
    weights = {f: float(raw[f]) for f in FACTORS}
    if any(w < 0 for w in weights.values()) or abs(sum(weights.values()) - 1) > 1e-6:
        raise ValueError(f"weights must be non-negative and sum to 1, got {weights}")
    return weights


@dataclass
class VulnScore:
    id: str
    cvss: float | None
    severity: float  # S
    epss: float  # E
    exploit: float  # X
    score: float
    contributions: dict[str, float]


@dataclass
class RankedComponent:
    name: str
    version: str | None
    ecosystem: str | None
    purl: str
    score: float  # 0..1
    factors: dict[str, float]
    contributions: dict[str, float]
    driving: VulnScore
    vulnerabilities: list[dict]
    depth: int | None
    path: list[str]
    release_date: str | None
    flags: list[str]
    max_severity: float
    max_cvss: float | None
    age_years: float | None = None
    rank: int = 0
    baseline_rank: int = 0
    explanation: str = ""
    top_factors: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return f"{self.name}@{self.version}" if self.version else self.name


def exploit_factor(v: dict) -> float:
    """X: 1.0 if in CISA KEV, 0.5 if NVD lists public exploit code, otherwise 0."""
    return 1.0 if v.get("kev") else 0.5 if v.get("exploit_reference") else 0.0


def age_factor(release_date: str | None, analysis_date: str) -> float | None:
    if not release_date:
        return None
    days = (date.fromisoformat(analysis_date) - date.fromisoformat(release_date[:10])).days
    return min(max(days, 0) / AGE_CAP_DAYS, 1.0)


def score_vulnerability(v: dict, w: dict[str, float]) -> VulnScore:
    s, e, x = float(v.get("severity", 0.5)), float(v.get("epss") or 0.0), exploit_factor(v)
    contrib = {"severity": w["severity"] * s, "exploit_probability": w["exploit_probability"] * e,
               "known_exploitation": w["known_exploitation"] * x}
    return VulnScore(v["id"], v.get("cvss"), s, e, x, sum(contrib.values()), contrib)


def score_component(c: dict, w: dict[str, float], analysis_date: str, max_depth: int) -> RankedComponent:
    flags = list(c.get("flags", []))
    for v in c["vulnerabilities"]:
        flags.extend(f"{v['id']}: {f}" for f in v.get("flags", []))
    vulns = [score_vulnerability(v, w) for v in c["vulnerabilities"]]
    # The driving vulnerability: highest VulnScore, then higher severity, then id (D1, Section 4).
    driving = sorted(vulns, key=lambda s: (-s.score, -s.severity, s.id))[0]

    depth = c.get("depth")
    if depth is None:
        depth_used = max_depth + 1
        flags.append(f"unreachable from root; depth treated as {depth_used}")
    else:
        depth_used = depth
    d = 1.0 / depth_used
    a = age_factor(c.get("release_date"), analysis_date)
    if a is None:
        a = 0.5
        if not any("release date" in f for f in flags):
            flags.append("release date not found; A = 0.50")

    factors = {"severity": driving.severity, "exploit_probability": driving.epss,
               "known_exploitation": driving.exploit, "depth": d, "age": a}
    contributions = dict(driving.contributions, depth=w["depth"] * d, age=w["age"] * a)
    cvss_values = [v["cvss"] for v in c["vulnerabilities"] if v.get("cvss") is not None]
    return RankedComponent(
        name=c["name"], version=c.get("version"), ecosystem=c.get("ecosystem"), purl=c["purl"],
        score=sum(contributions.values()), factors=factors, contributions=contributions, driving=driving,
        vulnerabilities=c["vulnerabilities"], depth=depth, path=c.get("path", []),
        release_date=c.get("release_date"), flags=flags,
        max_severity=max(v.severity for v in vulns), max_cvss=max(cvss_values, default=None),
        age_years=_years(c.get("release_date"), analysis_date))


def baseline_order(ranked: list[RankedComponent]) -> list[RankedComponent]:
    """CVSS-only: highest severity (same fallbacks as S), then more vulnerabilities, then name (D1, Section 7)."""
    return sorted(ranked, key=lambda r: (-round(r.max_severity, 6), -len(r.vulnerabilities), r.label))


def contextual_order(ranked: list[RankedComponent]) -> list[RankedComponent]:
    """Risk score, then more vulnerabilities, then higher severity, then name (D1, Section 4)."""
    return sorted(ranked, key=lambda r: (-round(r.score, 9), -len(r.vulnerabilities), -r.max_severity, r.label))


def rank(enrichment: dict, weights: dict[str, float] | None = None, max_depth: int | None = None) -> list[RankedComponent]:
    """Score every vulnerable component and return them in contextual order with both ranks filled in."""
    w = weights or default_weights()
    analysis_date = enrichment["run"]["analysis_date"]
    comps = enrichment["components"]
    if max_depth is None:
        max_depth = enrichment["run"].get("max_depth") or max((c["depth"] or 0 for c in comps), default=0)
    ranked = [score_component(c, w, analysis_date, max_depth) for c in comps if c["vulnerabilities"]]
    for i, r in enumerate(baseline_order(ranked), 1):
        r.baseline_rank = i
    ordered = contextual_order(ranked)
    for i, r in enumerate(ordered, 1):
        r.rank = i
        r.top_factors = [f for f, _ in sorted(r.contributions.items(), key=lambda kv: (-kv[1], FACTORS.index(kv[0])))[:2]]
        r.explanation = explain(r)
    return ordered


def _years(release_date: str | None, analysis_date: str | None) -> float | None:
    if not release_date or not analysis_date:
        return None
    return (date.fromisoformat(analysis_date) - date.fromisoformat(release_date[:10])).days / 365.25


def _factor_phrase(r: RankedComponent, f: str) -> str:
    pts = f"(+{r.contributions[f] * 100:.1f})"
    d = r.driving
    if f == "severity":
        return f"CVSS severity {d.cvss:.1f} {pts}" if d.cvss is not None else f"advisory severity {d.severity:.2f} {pts}"
    if f == "exploit_probability":
        return f"a {d.epss:.2f} EPSS exploit probability {pts}"
    if f == "known_exploitation":
        return f"listed in CISA KEV {pts}" if d.exploit == 1.0 else f"public exploit code listed in NVD {pts}"
    if f == "depth":
        return f"being a direct dependency {pts}" if r.factors["depth"] == 1.0 else f"its depth {pts}"
    return f"the version's age {pts}"


def explain(r: RankedComponent) -> str:
    """One sentence built from the two largest weighted contributions (D1, Section 5)."""
    d = r.driving
    cvss = f"CVSS {d.cvss:.1f}" if d.cvss is not None else "no CVSS score"
    p1, p2 = (_factor_phrase(r, f) for f in r.top_factors)
    if r.depth == 1:
        where = "direct dependency"
    elif r.depth is None:
        where = "not reachable from the application root"
    else:
        where = f"{r.depth} levels deep via {' → '.join(r.path)}"
    age = "version age unknown" if r.age_years is None else f"version {r.age_years:.1f} years old"
    n = len(r.vulnerabilities)
    text = (f"#{r.rank} {r.label} (score {r.score * 100:.1f}, baseline #{r.baseline_rank}): driven by {d.id} ({cvss}); "
            f"largest factors are {p1} and {p2}; {where}; {age}; {n} vulnerabilit{'y' if n == 1 else 'ies'}")
    flag_count = len(r.flags)
    if flag_count:
        text += f"; {flag_count} data-quality flag{'s' if flag_count != 1 else ''}"
    return text + "."


def ranking_record(r: RankedComponent) -> dict:
    return {
        "rank": r.rank,
        "baseline_rank": r.baseline_rank,
        "movement": r.baseline_rank - r.rank,
        "name": r.name,
        "version": r.version,
        "ecosystem": r.ecosystem,
        "purl": r.purl,
        "score": round(r.score * 100, 1),
        "factors": {f: round(v, 4) for f, v in r.factors.items()},
        "contributions": {f: round(v * 100, 2) for f, v in r.contributions.items()},
        "top_factors": r.top_factors,
        "driving_vulnerability": {k: v for k, v in asdict(r.driving).items() if k != "contributions"},
        "vulnerabilities": [{k: v.get(k) for k in ("id", "aliases", "cvss", "cvss_version", "severity", "epss",
                                                   "kev", "exploit_reference")} for v in r.vulnerabilities],
        "depth": r.depth,
        "path": r.path,
        "release_date": r.release_date,
        "flags": r.flags,
        "explanation": r.explanation,
    }


def write_outputs(out_dir: Path, enrichment: dict, ranked: list[RankedComponent], weights: dict[str, float],
                  extra_run: dict | None = None) -> dict[str, Path]:
    """Write ranking.json/.csv, baseline.csv, not-ranked.csv and run.json (D1, Section 6)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {k: out_dir / n for k, n in (("ranking_json", "ranking.json"), ("ranking_csv", "ranking.csv"),
                                         ("baseline_csv", "baseline.csv"), ("not_ranked_csv", "not-ranked.csv"),
                                         ("run_json", "run.json"))}
    records = [ranking_record(r) for r in ranked]
    paths["ranking_json"].write_text(json.dumps({"weights": weights, "components": records}, indent=2) + "\n",
                                     encoding="utf-8")

    with open(paths["ranking_csv"], "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["rank", "baseline_rank", "movement", "name", "version", "ecosystem", "score",
                    *[SHORT[x] for x in FACTORS], *[f"{SHORT[x]}_points" for x in FACTORS],
                    "driving_vulnerability", "driving_cvss", "driving_epss", "in_kev", "vulnerabilities",
                    "depth", "path", "release_date", "flags", "explanation"])
        for r, rec in zip(ranked, records):
            w.writerow([rec["rank"], rec["baseline_rank"], rec["movement"], r.name, r.version, r.ecosystem,
                        rec["score"], *[round(r.factors[x], 4) for x in FACTORS],
                        *[rec["contributions"][x] for x in FACTORS], r.driving.id, r.driving.cvss,
                        round(r.driving.epss, 5), r.driving.exploit == 1.0, len(r.vulnerabilities),
                        r.depth, " → ".join(r.path), r.release_date, len(r.flags), r.explanation])

    with open(paths["baseline_csv"], "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["baseline_rank", "name", "version", "max_cvss", "max_severity", "vulnerabilities", "contextual_rank"])
        for r in baseline_order(ranked):
            w.writerow([r.baseline_rank, r.name, r.version, r.max_cvss, round(r.max_severity, 4),
                        len(r.vulnerabilities), r.rank])

    with open(paths["not_ranked_csv"], "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["component", "status"])
        for purl in enrichment.get("not_vulnerable", []):
            w.writerow([purl, "no known vulnerabilities"])
        for n in enrichment.get("not_assessed", []):
            w.writerow([n.get("name") or n.get("bom_ref"), f"not assessed: {n.get('reason')}"])

    flag_counts: dict[str, int] = {}
    for r in ranked:
        for fl in r.flags:
            key = fl.split(": ", 1)[-1] if fl.startswith(("CVE-", "GHSA-", "PYSEC-", "GO-", "RUSTSEC-")) else fl
            key = key.split("; depth treated as")[0]
            flag_counts[key] = flag_counts.get(key, 0) + 1
    run = dict(enrichment["run"], weights=weights, ranked_components=len(ranked),
               not_vulnerable=len(enrichment.get("not_vulnerable", [])),
               not_assessed=len(enrichment.get("not_assessed", [])), flag_counts=flag_counts, **(extra_run or {}))
    paths["run_json"].write_text(json.dumps(run, indent=2) + "\n", encoding="utf-8")
    return paths
