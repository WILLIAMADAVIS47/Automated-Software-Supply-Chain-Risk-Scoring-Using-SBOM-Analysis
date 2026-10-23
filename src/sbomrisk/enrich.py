"""Vulnerability enrichment (Task G).

For every component in a parsed SBOM this module finds the known
vulnerabilities (OSV) and attaches the data the scoring factors need:
CVSS base score (NVD, factor S), EPSS probability (FIRST, factor E),
CISA KEV membership and NVD exploit references (factor X), and the
version's release date from the package registry (factor A). Depth
(factor D) comes from the dependency graph.

Every HTTP response is cached on disk, so a run can be repeated exactly
with --offline. Only the Python standard library is used.

Specification: "docs/D1 Scoring Specification.docx", Sections 2 and 3.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Callable

from . import __version__
from .graph import DependencyGraph
from .models import Component

OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{id}"
NVD_CVE = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
EPSS_API = "https://api.first.org/data/v1/epss?cve={cves}"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Qualitative ratings used when no CVSS base score is available (D1, Section 3, factor S).
QUALITATIVE_SEVERITY = {"CRITICAL": 0.95, "HIGH": 0.80, "MODERATE": 0.55, "MEDIUM": 0.55, "LOW": 0.25}

USER_AGENT = f"sbomrisk/{__version__} (CS 690 Graduate Research Project)"


class OfflineMiss(Exception):
    """Raised in offline mode when a response is not in the cache."""


class Fetcher:
    """HTTP GET/POST with an on-disk cache, retries and per-host pacing."""

    def __init__(self, cache_dir: str | Path, offline: bool = False, nvd_api_key: str | None = None,
                 transport: Callable[[urllib.request.Request], bytes] | None = None, sleep=time.sleep):
        self.cache_dir = Path(cache_dir)
        self.offline = offline
        self.nvd_api_key = nvd_api_key
        self.transport = transport or self._urlopen
        self.sleep = sleep
        self._last_call: dict[str, float] = {}
        self.calls = 0
        self.cache_hits = 0

    @staticmethod
    def _urlopen(req: urllib.request.Request) -> bytes:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.read()

    def _cache_path(self, key: str) -> Path:
        digest = hashlib.sha256(key.encode()).hexdigest()[:32]
        host = urllib.parse.urlparse(key.split(" ", 1)[-1]).netloc or "misc"
        return self.cache_dir / host / f"{digest}.json"

    def _pace(self, host: str) -> None:
        # NVD allows 5 requests per 30 s without an API key and 50 with one.
        gap = {"services.nvd.nist.gov": 0.7 if self.nvd_api_key else 6.5}.get(host, 0.2)
        wait = self._last_call.get(host, 0) + gap - time.monotonic()
        if wait > 0:
            self.sleep(wait)
        self._last_call[host] = time.monotonic()

    def get_json(self, url: str, body: dict | None = None):
        key = f"POST {url} {json.dumps(body, sort_keys=True)}" if body is not None else url
        path = self._cache_path(key)
        if path.exists():
            self.cache_hits += 1
            return json.loads(path.read_text(encoding="utf-8"))["response"]
        if self.offline:
            raise OfflineMiss(key)

        host = urllib.parse.urlparse(url).netloc
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if host == "services.nvd.nist.gov" and self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"

        delay = 2.0
        for attempt in range(6):
            self._pace(host)
            req = urllib.request.Request(url, data=data, headers=headers, method="POST" if data else "GET")
            try:
                self.calls += 1
                raw = self.transport(req)
                break
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    raw = b"null"
                    break
                if exc.code in (403, 429, 500, 502, 503, 504) and attempt < 5:
                    self.sleep(delay)
                    delay *= 2
                    continue
                raise
            except urllib.error.URLError:
                if attempt < 5:
                    self.sleep(delay)
                    delay *= 2
                    continue
                raise
        response = json.loads(raw) if raw else None
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"key": key, "fetched": datetime.now(timezone.utc).isoformat(),
                                    "response": response}), encoding="utf-8")
        return response


@dataclass
class Vulnerability:
    id: str
    aliases: list[str]
    cves: list[str]
    summary: str = ""
    cvss: float | None = None
    cvss_version: str | None = None
    severity_source: str | None = None  # "nvd", "qualitative" or "default"
    severity: float = 0.5  # factor S input, 0..1
    epss: float | None = None
    epss_percentile: float | None = None
    kev: bool = False
    exploit_reference: bool = False
    flags: list[str] = field(default_factory=list)


@dataclass
class EnrichedComponent:
    purl: str
    name: str
    version: str | None
    ecosystem: str | None
    depth: int | None
    path: list[str]
    bom_refs: list[str]
    release_date: str | None = None
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)


def _purl_for_query(c: Component) -> str:
    """The component's purl without qualifiers or subpath, as OSV expects."""
    return c.purl_string.split("#", 1)[0].split("?", 1)[0]


def merge_duplicates(graph: DependencyGraph) -> tuple[list[EnrichedComponent], list[dict]]:
    """One entry per package URL at its shallowest depth (D1, Section 2); unassessable ones listed apart."""
    by_purl: dict[str, EnrichedComponent] = {}
    not_assessed = []
    for c in graph.components.values():
        if not c.purl or not c.version or not c.osv_ecosystem:
            reason = "no package URL" if not c.purl else ("no version" if not c.version else
                                                          f"ecosystem {c.ecosystem!r} not covered by OSV")
            not_assessed.append({"bom_ref": c.bom_ref, "name": c.display_name, "reason": reason})
            continue
        key = _purl_for_query(c)
        entry = by_purl.get(key)
        if entry is None:
            entry = by_purl[key] = EnrichedComponent(
                purl=key, name=c.purl.coordinate, version=c.version, ecosystem=c.ecosystem,
                depth=c.depth, path=[], bom_refs=[])
        entry.bom_refs.append(c.bom_ref)
        if c.depth is not None and (entry.depth is None or c.depth < entry.depth):
            entry.depth = c.depth
    for entry in by_purl.values():
        best = min(entry.bom_refs, key=lambda r: graph.components[r].depth or 10**6)
        entry.path = [graph.components[r].display_name for r in graph.path_to(best)]
        if entry.depth is None:
            entry.flags.append("unreachable from root")
    return sorted(by_purl.values(), key=lambda e: (e.depth or 10**6, e.name)), not_assessed


def osv_vulnerability_ids(fetcher: Fetcher, purls: list[str]) -> dict[str, list[str]]:
    """purl -> OSV ids affecting that exact version, using the batch endpoint (1,000 queries per call)."""
    result: dict[str, list[str]] = {p: [] for p in purls}
    pending = [(p, None) for p in purls]
    while pending:
        batch, pending = pending[:1000], pending[1000:]
        queries = [{"package": {"purl": p}, **({"page_token": t} if t else {})} for p, t in batch]
        resp = fetcher.get_json(OSV_QUERYBATCH, {"queries": queries}) or {}
        for (p, _), r in zip(batch, resp.get("results", [])):
            result[p].extend(v["id"] for v in r.get("vulns", []) or [])
            if r.get("next_page_token"):
                pending.append((p, r["next_page_token"]))
    return result


def _group_aliases(records: list[dict]) -> list[list[dict]]:
    """Merge OSV records that are aliases of one another (e.g. a GHSA and its CVE)."""
    parent: dict[str, str] = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for r in records:
        for a in r.get("aliases", []) or []:
            parent[find(a)] = find(r["id"])
        find(r["id"])
    groups: dict[str, list[dict]] = {}
    for r in records:
        groups.setdefault(find(r["id"]), []).append(r)
    return list(groups.values())


def _qualitative(records: list[dict]) -> float | None:
    for r in records:
        sev = str((r.get("database_specific") or {}).get("severity") or "").upper()
        if sev in QUALITATIVE_SEVERITY:
            return QUALITATIVE_SEVERITY[sev]
    return None


def nvd_cvss(record) -> tuple[float | None, str | None, bool]:
    """(base score, CVSS version, has 'Exploit' reference) from an NVD API v2 response."""
    vulns = (record or {}).get("vulnerabilities") or []
    if not vulns:
        return None, None, False
    cve = vulns[0].get("cve", {})
    metrics = cve.get("metrics", {})
    score = version = None
    # Preference order from D1: v3.1, then v4.0, then v3.0, then v2.
    for key, label in (("cvssMetricV31", "3.1"), ("cvssMetricV40", "4.0"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key) or []
        if entries:
            primary = [m for m in entries if m.get("type") == "Primary"] or entries
            score, version = float(primary[0]["cvssData"]["baseScore"]), label
            break
    exploit = any("Exploit" in (ref.get("tags") or []) for ref in cve.get("references", []))
    return score, version, exploit


def build_vulnerabilities(fetcher: Fetcher, ids: list[str]) -> list[Vulnerability]:
    records = []
    for vid in sorted(set(ids)):
        rec = fetcher.get_json(OSV_VULN.format(id=urllib.parse.quote(vid)))
        if rec and not rec.get("withdrawn"):
            records.append(rec)
    vulns = []
    for group in _group_aliases(records):
        all_ids = sorted({r["id"] for r in group} | {a for r in group for a in r.get("aliases", []) or []})
        cves = [i for i in all_ids if i.startswith("CVE-")]
        primary = next((r for r in group if r["id"].startswith("GHSA-")), group[0])
        v = Vulnerability(id=cves[0] if cves else primary["id"], aliases=all_ids, cves=cves,
                          summary=(primary.get("summary") or primary.get("details") or "")[:200])
        qualitative = _qualitative(group)
        if qualitative is not None:
            v.severity, v.severity_source = qualitative, "qualitative"
        else:
            v.severity_source = "default"
            v.flags.append("no severity data; S = 0.50")
        if not cves:
            v.flags.append("no CVE alias; EPSS and KEV not applicable")
        vulns.append(v)
    return vulns


def add_nvd(fetcher: Fetcher, vulns: list[Vulnerability]) -> None:
    for v in vulns:
        for cve in v.cves:
            score, version, exploit = nvd_cvss(fetcher.get_json(NVD_CVE.format(cve=cve)))
            v.exploit_reference = v.exploit_reference or exploit
            if score is not None and (v.cvss is None or score > v.cvss):
                v.cvss, v.cvss_version = score, version
        if v.cvss is not None:
            v.severity, v.severity_source = v.cvss / 10, "nvd"
            v.flags = [f for f in v.flags if not f.startswith("no severity")]


def add_epss(fetcher: Fetcher, vulns: list[Vulnerability], on_date: str | None) -> None:
    cves = sorted({c for v in vulns for c in v.cves})
    scores: dict[str, tuple[float, float]] = {}
    for i in range(0, len(cves), 100):
        url = EPSS_API.format(cves=",".join(cves[i:i + 100]))
        if on_date:
            url += f"&date={on_date}"
        for row in (fetcher.get_json(url) or {}).get("data", []):
            scores[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
    for v in vulns:
        found = [scores[c] for c in v.cves if c in scores]
        if found:
            v.epss, v.epss_percentile = max(found)
        elif v.cves:
            v.flags.append("no EPSS score; E = 0")


def load_kev(fetcher: Fetcher) -> set[str]:
    feed = fetcher.get_json(KEV_FEED) or {}
    return {row["cveID"] for row in feed.get("vulnerabilities", [])}


def _go_escape(path: str) -> str:
    return "".join(f"!{ch.lower()}" if ch.isupper() else ch for ch in path)


def release_date(fetcher: Fetcher, e: EnrichedComponent) -> str | None:
    """The version's publication date from its registry, as YYYY-MM-DD, or None."""
    name, ver = e.name, e.version
    try:
        if e.ecosystem == "npm":
            doc = fetcher.get_json(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}") or {}
            stamp = (doc.get("time") or {}).get(ver)
        elif e.ecosystem == "pypi":
            doc = fetcher.get_json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/{urllib.parse.quote(ver)}/json") or {}
            stamp = min((u["upload_time_iso_8601"] for u in doc.get("urls", [])), default=None)
        elif e.ecosystem == "golang":
            doc = fetcher.get_json(f"https://proxy.golang.org/{_go_escape(name)}/@v/{_go_escape(ver)}.info") or {}
            stamp = doc.get("Time")
        elif e.ecosystem == "maven":
            group, _, artifact = name.partition(":")
            q = urllib.parse.quote(f'g:"{group}" AND a:"{artifact}" AND v:"{ver}"')
            doc = fetcher.get_json(f"https://search.maven.org/solrsearch/select?q={q}&wt=json") or {}
            docs = (doc.get("response") or {}).get("docs") or []
            stamp = datetime.fromtimestamp(docs[0]["timestamp"] / 1000, timezone.utc).isoformat() if docs else None
        else:
            stamp = None
    except (urllib.error.URLError, OfflineMiss, ValueError, KeyError):
        stamp = None
    return stamp[:10] if stamp else None


def sha256_file(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def enrich(graph: DependencyGraph, fetcher: Fetcher, analysis_date: str | None = None,
           progress: Callable[[str], None] = lambda msg: None) -> dict:
    """Run the full enrichment and return a JSON-serializable result."""
    analysis_date = analysis_date or date.today().isoformat()
    entries, not_assessed = merge_duplicates(graph)

    progress(f"querying OSV for {len(entries)} components")
    ids_by_purl = osv_vulnerability_ids(fetcher, [e.purl for e in entries])
    vulnerable = [e for e in entries if ids_by_purl[e.purl]]

    progress(f"fetching {sum(len(set(ids_by_purl[e.purl])) for e in vulnerable)} OSV records")
    for e in vulnerable:
        e.vulnerabilities = build_vulnerabilities(fetcher, ids_by_purl[e.purl])
    all_vulns = [v for e in vulnerable for v in e.vulnerabilities]

    n_cves = len({c for v in all_vulns for c in v.cves})
    progress(f"fetching CVSS from NVD for {n_cves} CVEs" + ("" if fetcher.nvd_api_key else
             " (no NVD API key, so this is paced at about 6 seconds per CVE)"))
    add_nvd(fetcher, all_vulns)

    progress("fetching EPSS scores and the CISA KEV catalog")
    today = date.today().isoformat()
    add_epss(fetcher, all_vulns, None if analysis_date == today else analysis_date)
    kev = load_kev(fetcher)
    for v in all_vulns:
        v.kev = any(c in kev for c in v.cves)

    progress(f"fetching release dates for {len(vulnerable)} vulnerable components")
    for e in vulnerable:
        e.release_date = release_date(fetcher, e)
        if e.release_date is None:
            e.flags.append("release date not found; A = 0.50")

    sbom = graph.sbom
    return {
        "run": {
            "tool": f"sbomrisk {__version__}",
            "analysis_date": analysis_date,
            "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "sbom": str(sbom.source),
            "sbom_sha256": sha256_file(sbom.source) if Path(str(sbom.source)).exists() else None,
            "root": sbom.root.display_name if sbom.root else None,
            "sources": {"osv": OSV_QUERYBATCH, "nvd": NVD_CVE.split("?")[0], "epss": EPSS_API.split("?")[0],
                        "kev": KEV_FEED},
            "kev_entries": len(kev),
            "http_calls": fetcher.calls,
            "cache_hits": fetcher.cache_hits,
        },
        "summary": {
            "components": len(entries),
            "vulnerable_components": len(vulnerable),
            "vulnerabilities": len(all_vulns),
            "with_cvss": sum(v.cvss is not None for v in all_vulns),
            "with_epss": sum(v.epss is not None for v in all_vulns),
            "in_kev": sum(v.kev for v in all_vulns),
            "not_assessed": len(not_assessed),
        },
        "components": [asdict(e) for e in vulnerable],
        "not_vulnerable": [e.purl for e in entries if not ids_by_purl[e.purl]],
        "not_assessed": not_assessed,
    }


def default_nvd_key() -> str | None:
    return os.environ.get("NVD_API_KEY") or None


def print_summary(result: dict, out=None) -> None:
    out = out or sys.stdout
    s = result["summary"]
    print(f"  components checked: {s['components']}  vulnerable: {s['vulnerable_components']}  "
          f"vulnerabilities: {s['vulnerabilities']}", file=out)
    print(f"  with CVSS: {s['with_cvss']}  with EPSS: {s['with_epss']}  in CISA KEV: {s['in_kev']}  "
          f"not assessed: {s['not_assessed']}", file=out)
    for c in result["components"][:10]:
        worst = max(c["vulnerabilities"], key=lambda v: v["severity"], default=None)
        if worst:
            cvss = f"CVSS {worst['cvss']}" if worst["cvss"] is not None else f"severity {worst['severity']:.2f}"
            epss = f"EPSS {worst['epss']:.3f}" if worst["epss"] is not None else "EPSS n/a"
            print(f"    {c['name']}@{c['version']} (depth {c['depth']}): {len(c['vulnerabilities'])} vulns, "
                  f"worst {worst['id']} {cvss}, {epss}{', KEV' if worst['kev'] else ''}", file=out)
