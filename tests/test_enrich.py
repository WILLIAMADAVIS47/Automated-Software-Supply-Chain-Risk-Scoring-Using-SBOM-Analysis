"""Enrichment tests with recorded-style API responses; no network access is used."""

import json
import urllib.error
from io import BytesIO

import pytest

from sbomrisk import cli
from sbomrisk.enrich import (EPSS_API, KEV_FEED, NVD_CVE, OSV_QUERYBATCH, OSV_VULN, Fetcher, OfflineMiss,
                             enrich, merge_duplicates, nvd_cvss)
from sbomrisk.graph import DependencyGraph
from sbomrisk.parser import parse_document

DOC = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "metadata": {"component": {"bom-ref": "app", "name": "app", "version": "1.0"}},
    "components": [
        {"bom-ref": "django", "name": "django", "version": "4.1.7", "purl": "pkg:pypi/django@4.1.7"},
        {"bom-ref": "sqlparse", "name": "sqlparse", "version": "0.4.3", "purl": "pkg:pypi/sqlparse@0.4.3"},
        {"bom-ref": "lodash-a", "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"},
        {"bom-ref": "lodash-b", "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"},
        {"bom-ref": "nopurl", "name": "vendored-thing", "version": "1"},
    ],
    "dependencies": [
        {"ref": "app", "dependsOn": ["django", "lodash-a", "nopurl"]},
        {"ref": "django", "dependsOn": ["sqlparse"]},
        {"ref": "sqlparse", "dependsOn": ["lodash-b"]},
    ],
}

NVD_RECORD = {"vulnerabilities": [{"cve": {
    "metrics": {
        "cvssMetricV31": [{"type": "Secondary", "cvssData": {"baseScore": 5.0}},
                          {"type": "Primary", "cvssData": {"baseScore": 7.5}}],
        "cvssMetricV2": [{"type": "Primary", "cvssData": {"baseScore": 5.0}}],
    },
    "references": [{"url": "https://example.org/poc", "tags": ["Exploit", "Third Party Advisory"]}],
}}]}

RESPONSES = {
    OSV_VULN.format(id="GHSA-aaaa"): {"id": "GHSA-aaaa", "aliases": ["CVE-2023-0001"], "summary": "Django DoS",
                                      "database_specific": {"severity": "HIGH"}},
    OSV_VULN.format(id="PYSEC-1"): {"id": "PYSEC-1", "aliases": ["CVE-2023-0001", "GHSA-aaaa"]},
    OSV_VULN.format(id="GHSA-old"): {"id": "GHSA-old", "withdrawn": "2023-01-01T00:00:00Z"},
    OSV_VULN.format(id="GHSA-lodash"): {"id": "GHSA-lodash", "aliases": ["CVE-2021-23337"],
                                        "database_specific": {"severity": "HIGH"}},
    NVD_CVE.format(cve="CVE-2023-0001"): NVD_RECORD,
    NVD_CVE.format(cve="CVE-2021-23337"): {"vulnerabilities": []},
    EPSS_API.format(cves="CVE-2021-23337,CVE-2023-0001"): {"data": [
        {"cve": "CVE-2023-0001", "epss": "0.42", "percentile": "0.97"}]},
    KEV_FEED: {"vulnerabilities": [{"cveID": "CVE-2023-0001"}]},
    "https://pypi.org/pypi/django/4.1.7/json": {"urls": [{"upload_time_iso_8601": "2023-02-14T08:00:00Z"}]},
    "https://registry.npmjs.org/lodash": {"time": {"4.17.20": "2020-08-13T16:53:54.152Z"}},
}


class FakeTransport:
    def __init__(self):
        self.requests = []

    def __call__(self, req):
        url = req.full_url.split("&date=")[0]  # EPSS history requests share the same canned response
        self.requests.append(url)
        if url == OSV_QUERYBATCH:
            queries = json.loads(req.data)["queries"]
            table = {"pkg:pypi/django@4.1.7": ["GHSA-aaaa", "PYSEC-1", "GHSA-old"],
                     "pkg:npm/lodash@4.17.20": ["GHSA-lodash"]}
            return json.dumps({"results": [{"vulns": [{"id": i} for i in table.get(q["package"]["purl"], [])]}
                                           for q in queries]}).encode()
        if url not in RESPONSES:
            raise urllib.error.HTTPError(url, 404, "not found", {}, BytesIO())
        return json.dumps(RESPONSES[url]).encode()


@pytest.fixture
def run(tmp_path):
    transport = FakeTransport()
    fetcher = Fetcher(tmp_path / "cache", transport=transport, sleep=lambda s: None)
    graph = DependencyGraph(parse_document(DOC, source="test.cdx.json"))
    return enrich(graph, fetcher, analysis_date="2026-10-23"), transport, tmp_path


def test_duplicate_installs_merge_at_shallowest_depth():
    graph = DependencyGraph(parse_document(DOC))
    entries, not_assessed = merge_duplicates(graph)
    lodash = next(e for e in entries if e.name == "lodash")
    assert lodash.depth == 1 and sorted(lodash.bom_refs) == ["lodash-a", "lodash-b"]
    assert [n["reason"] for n in not_assessed] == ["no package URL"]


def test_aliases_merge_and_withdrawn_records_are_dropped(run):
    result, _, _ = run
    django = next(c for c in result["components"] if c["name"] == "django")
    assert len(django["vulnerabilities"]) == 1
    v = django["vulnerabilities"][0]
    assert v["id"] == "CVE-2023-0001"
    assert set(v["aliases"]) == {"CVE-2023-0001", "GHSA-aaaa", "PYSEC-1"}


def test_factor_inputs_are_attached(run):
    result, _, _ = run
    django = next(c for c in result["components"] if c["name"] == "django")
    v = django["vulnerabilities"][0]
    assert (v["cvss"], v["cvss_version"], v["severity"]) == (7.5, "3.1", 0.75)
    assert (v["epss"], v["kev"], v["exploit_reference"]) == (0.42, True, True)
    assert django["release_date"] == "2023-02-14" and django["depth"] == 1


def test_missing_nvd_score_falls_back_to_qualitative_rating(run):
    result, _, _ = run
    lodash = next(c for c in result["components"] if c["name"] == "lodash")
    v = lodash["vulnerabilities"][0]
    assert v["cvss"] is None and v["severity_source"] == "qualitative" and v["severity"] == 0.80
    assert v["epss"] is None and "no EPSS score; E = 0" in v["flags"]


def test_summary_and_unaffected_components(run):
    result, _, _ = run
    assert result["summary"] == {"components": 3, "vulnerable_components": 2, "vulnerabilities": 2,
                                 "with_cvss": 1, "with_epss": 1, "in_kev": 1, "not_assessed": 1}
    assert result["not_vulnerable"] == ["pkg:pypi/sqlparse@0.4.3"]


def test_offline_rerun_uses_only_the_cache(run):
    result, _, tmp_path = run
    graph = DependencyGraph(parse_document(DOC, source="test.cdx.json"))
    offline = Fetcher(tmp_path / "cache", offline=True)
    again = enrich(graph, offline, analysis_date="2026-10-23")
    assert offline.calls == 0
    assert again["components"] == result["components"]
    with pytest.raises(OfflineMiss):
        Fetcher(tmp_path / "empty", offline=True).get_json(KEV_FEED)


def test_nvd_prefers_primary_v31_score():
    assert nvd_cvss(NVD_RECORD) == (7.5, "3.1", True)
    assert nvd_cvss({"vulnerabilities": []}) == (None, None, False)


def test_cli_enrich_offline_writes_output(run, capsys):
    _, _, tmp_path = run
    sbom = tmp_path / "test.cdx.json"
    sbom.write_text(json.dumps(DOC))
    out = tmp_path / "out.json"
    code = cli.main(["enrich", str(sbom), "--offline", "--cache-dir", str(tmp_path / "cache"),
                     "--date", "2026-10-23", "-o", str(out)])
    assert code == 0
    assert json.loads(out.read_text())["summary"]["in_kev"] == 1
    assert "in CISA KEV: 1" in capsys.readouterr().out
