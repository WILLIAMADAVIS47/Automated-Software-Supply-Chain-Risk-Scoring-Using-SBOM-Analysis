"""Scoring, ranking, baseline and evaluation tests, using the worked examples from D1."""

import json

import pytest

from sbomrisk import cli
from sbomrisk.evaluate import evaluate_project, kendall_tau, overall, varied_weights
from sbomrisk.score import FACTORS, default_weights, load_weights, rank

ANALYSIS_DATE = "2026-10-23"


def vuln(vid, cvss=None, severity=None, epss=None, kev=False, exploit=False, flags=()):
    return {"id": vid, "aliases": [vid], "cves": [vid] if vid.startswith("CVE") else [], "cvss": cvss,
            "severity": severity if severity is not None else (cvss / 10 if cvss is not None else 0.5),
            "epss": epss, "kev": kev, "exploit_reference": exploit, "flags": list(flags)}


def comp(name, vulns, depth=1, release="2024-01-01", path=None):
    return {"purl": f"pkg:pypi/{name}@1.0", "name": name, "version": "1.0", "ecosystem": "pypi", "depth": depth,
            "path": path or [f"{name}@1.0"], "release_date": release, "vulnerabilities": vulns, "flags": []}


def enrichment(*components):
    return {"run": {"analysis_date": ANALYSIS_DATE}, "summary": {"components": len(components), "vulnerabilities":
            sum(len(c["vulnerabilities"]) for c in components), "not_assessed": 0},
            "components": list(components), "not_vulnerable": [], "not_assessed": []}


# D1, Section 4: the two worked examples.
EXPLOITED = comp("exploited", [vuln("CVE-2023-0001", 9.8, epss=0.94, kev=True)], release="2023-04-24")
QUIET = comp("quiet", [vuln("CVE-2023-0002", 9.8, epss=0.002)], depth=4, release="2026-04-24",
             path=["a@1", "b@1", "c@1", "quiet@1.0"])


def test_default_weights_match_d1():
    assert default_weights() == {"severity": 0.30, "exploit_probability": 0.25, "known_exploitation": 0.20,
                                 "depth": 0.15, "age": 0.10}
    with pytest.raises(ValueError):
        load_weights(json.dumps({f: 0.3 for f in FACTORS}))


def test_worked_examples_from_d1():
    ranked = rank(enrichment(EXPLOITED, QUIET))
    by_name = {r.name: r for r in ranked}
    assert round(by_name["exploited"].score * 100, 1) == 94.9
    assert round(by_name["quiet"].score * 100, 1) == 34.2
    assert [r.name for r in ranked] == ["exploited", "quiet"]


def test_baseline_ties_break_on_vulnerability_count_then_name():
    a = comp("alpha", [vuln("CVE-1", 9.8)])
    b = comp("beta", [vuln("CVE-2", 9.8), vuln("CVE-3", 5.0)])
    c = comp("gamma", [vuln("CVE-4", 7.0, epss=0.9, kev=True)])
    ranked = {r.name: r for r in rank(enrichment(a, b, c))}
    assert (ranked["beta"].baseline_rank, ranked["alpha"].baseline_rank, ranked["gamma"].baseline_rank) == (1, 2, 3)
    assert ranked["gamma"].rank == 1


def test_driving_vulnerability_keeps_factors_together():
    c = comp("mixed", [vuln("CVE-HIGH", 9.8, epss=0.001), vuln("CVE-KEV", 6.0, epss=0.70, kev=True)])
    r = rank(enrichment(c))[0]
    assert r.driving.id == "CVE-KEV"
    assert r.factors["severity"] == pytest.approx(0.60)  # not 0.98 from the other CVE
    assert r.max_severity == pytest.approx(0.98)  # the baseline still sees the 9.8


def test_missing_data_fallbacks_are_flagged():
    c = comp("orphan", [vuln("GHSA-x", severity=0.80, flags=["no CVE alias; EPSS and KEV not applicable"])],
             depth=None, release=None)
    r = rank(enrichment(c), max_depth=3)[0]
    assert r.factors["depth"] == pytest.approx(1 / 4)
    assert r.factors["age"] == 0.5 and r.factors["exploit_probability"] == 0.0
    assert any("unreachable" in f for f in r.flags) and any("release date" in f for f in r.flags)


def test_explanation_names_driver_factors_path_and_baseline():
    r = rank(enrichment(EXPLOITED, QUIET))[1]
    assert r.explanation.startswith("#2 quiet@1.0 (score 34.2, baseline #2): driven by CVE-2023-0002 (CVSS 9.8)")
    assert "4 levels deep via a@1 → b@1 → c@1 → quiet@1.0" in r.explanation
    assert "version 0.5 years old" in r.explanation


def test_kendall_tau_and_weight_variation():
    assert kendall_tau(list("abcd"), list("abcd")) == 1.0
    assert kendall_tau(list("abcd"), list("dcba")) == -1.0
    w = varied_weights(default_weights(), "depth", 0.10)
    assert w["depth"] == pytest.approx(0.25) and sum(w.values()) == pytest.approx(1.0)
    assert w["severity"] / w["exploit_probability"] == pytest.approx(0.30 / 0.25)


def test_evaluation_runs_twenty_sensitivity_runs():
    comps = [comp(f"p{i}", [vuln(f"CVE-{i}", 5 + i * 0.4, epss=(i % 3) / 10, exploit=i % 4 == 0)],
                  depth=1 + i % 3, release=f"20{14 + i}-06-01") for i in range(12)]
    result = evaluate_project("synthetic", enrichment(*comps), default_weights())
    assert result["sensitivity"]["runs"] == 20
    assert result["differentiation"]["top10_meaningful"]
    assert set(overall([result])) >= {"differentiation_met", "justification_met", "stability_met"}


def test_cli_rank_and_evaluate(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    sbom = tmp_path / "data" / "sboms" / "demo.cdx.json"
    sbom.parent.mkdir(parents=True)
    sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5",
                                "metadata": {"component": {"bom-ref": "app", "name": "app"}}, "components": []}))
    assert cli.main(["rank", str(sbom)]) == 4  # nothing enriched yet
    folder = tmp_path / "results" / f"demo-{ANALYSIS_DATE}"
    folder.mkdir(parents=True)
    (folder / "enrichment.json").write_text(json.dumps(enrichment(EXPLOITED, QUIET)))
    assert cli.main(["rank", str(sbom)]) == 0
    for name in ("ranking.json", "ranking.csv", "baseline.csv", "not-ranked.csv", "run.json"):
        assert (folder / name).exists()
    assert "#1 exploited@1.0 (score 94.9" in capsys.readouterr().out
    assert cli.main(["evaluate", "-o", str(tmp_path / "eval")]) == 0
    assert json.loads((tmp_path / "eval" / "evaluation.json").read_text())["projects"][0]["project"] == "demo"
