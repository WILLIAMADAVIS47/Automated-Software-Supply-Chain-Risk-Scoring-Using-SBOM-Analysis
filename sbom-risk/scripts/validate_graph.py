"""Validate the parser's components, versions and dependency depths against each
ecosystem's own dependency tool (independent ground truth).

Usage:
  python scripts/validate_graph.py npm   SBOM.json  npm-ls.json        # npm ls --all --omit=dev --package-lock-only --json
  python scripts/validate_graph.py pip   SBOM.json  pipdeptree.json    # pipdeptree --json (run inside the project's venv)
  python scripts/validate_graph.py maven SBOM.json  mvn-tree.txt       # mvn dependency:tree -DoutputFile=mvn-tree.txt
  python scripts/validate_graph.py go    SBOM.json  go-list.json       # go list -m -json all

Prints a summary and exits 1 if any check falls below its threshold.
"""

from __future__ import annotations

import json
import re
import sys
from collections import deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sbomrisk.graph import DependencyGraph  # noqa: E402
from sbomrisk.parser import parse_file  # noqa: E402


def norm_py(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def sbom_index(graph: DependencyGraph, key=lambda c: c.purl.coordinate if c.purl else c.name):
    """{(name, version): depth}. A package installed in several places (npm nests copies) gets its shallowest depth."""
    index: dict = {}
    for c in graph.components.values():
        k = (key(c), c.version)
        if c.depth is not None and (k not in index or c.depth < index[k]):
            index[k] = c.depth
    return index


def npm_real_name(alias: str, node: dict) -> str:
    """npm aliases ("string-width-cjs": "npm:string-width@4.2.3") install under another name; recover the real one."""
    m = re.search(r"registry\.npmjs\.org/(.+?)/-/", node.get("resolved") or "")
    return m.group(1).replace("%2f", "/").replace("%2F", "/") if m else alias


def compare_depths(label: str, ours: dict, theirs: dict) -> bool:
    common = set(ours) & set(theirs)
    only_ours, only_theirs = sorted(set(ours) - set(theirs)), sorted(set(theirs) - set(ours))
    same_depth = [k for k in common if ours[k] == theirs[k]]
    pct_found = 100 * len(common) / max(len(theirs), 1)
    pct_depth = 100 * len(same_depth) / max(len(common), 1)
    print(f"{label}")
    print(f"  native tool components: {len(theirs)}   SBOM components: {len(ours)}   matched name+version: {len(common)} ({pct_found:.1f}%)")
    print(f"  same depth: {len(same_depth)} of {len(common)} ({pct_depth:.1f}%)")
    for title, items in (("only in SBOM", only_ours), ("only in native tool", only_theirs)):
        if items:
            print(f"  {title} ({len(items)}): " + ", ".join(f"{n}@{v}" for n, v in items[:8]) + (" ..." if len(items) > 8 else ""))
    diffs = sorted(k for k in common if ours[k] != theirs[k])
    if diffs:
        print("  depth differences: " + ", ".join(f"{n}@{v} sbom={ours[(n, v)]} native={theirs[(n, v)]}" for n, v in diffs[:8]))
    ok = pct_found >= 98 and pct_depth >= 98
    print(f"  RESULT: {'PASS' if ok else 'CHECK'} (thresholds: 98% matched, 98% same depth)")
    return ok


def validate_npm(graph: DependencyGraph, native: Path) -> bool:
    tree = json.loads(native.read_text())
    depths: dict = {}
    queue = deque((name, node, 1) for name, node in tree.get("dependencies", {}).items())
    while queue:
        name, node, depth = queue.popleft()
        key = (npm_real_name(name, node), node.get("version"))
        if key in depths or node.get("missing") or not node.get("version"):
            continue
        depths[key] = depth
        queue.extend((n, child, depth + 1) for n, child in node.get("dependencies", {}).items())
    return compare_depths("npm (npm ls)", sbom_index(graph), depths)


def validate_pip(graph: DependencyGraph, native: Path) -> bool:
    rows = json.loads(native.read_text())
    ignore = {"pip", "setuptools", "wheel", "pipdeptree", "packaging"}
    theirs_edges = {
        (norm_py(r["package"]["key"]), norm_py(d["key"]))
        for r in rows
        for d in r["dependencies"]
        if norm_py(r["package"]["key"]) not in ignore
    }
    by_ref = {ref: norm_py(c.name) for ref, c in graph.components.items()}
    ours_edges = {(by_ref[ref], by_ref[child]) for ref, c in graph.components.items() for child in c.children}
    theirs_pkgs = {(norm_py(r["package"]["key"]), r["package"]["installed_version"]) for r in rows} - {
        (n, v) for n, v in ((norm_py(r["package"]["key"]), r["package"]["installed_version"]) for r in rows) if n in ignore
    }
    ours_pkgs = {(norm_py(c.name), c.version) for c in graph.components.values()}
    print("pip (pipdeptree)")
    print(f"  packages: native {len(theirs_pkgs)}, SBOM {len(ours_pkgs)}, matched name+version {len(ours_pkgs & theirs_pkgs)}")
    print(f"  dependency edges: native {len(theirs_edges)}, SBOM {len(ours_edges)}, matched {len(ours_edges & theirs_edges)}")
    for title, items in (("edges only in SBOM", ours_edges - theirs_edges), ("edges only in native", theirs_edges - ours_edges)):
        if items:
            print(f"  {title}: " + ", ".join(f"{a}->{b}" for a, b in sorted(items)[:8]))
    ok = ours_pkgs == theirs_pkgs and ours_edges == theirs_edges
    print("  note: pip has no notion of the application's direct dependencies, so depth is not compared; edges are.")
    print(f"  RESULT: {'PASS' if ok else 'CHECK'} (threshold: identical packages and edges)")
    return ok


MVN_LINE = re.compile(r"^(?P<indent>[| +\\-]*)(?P<coord>[^\s:]+:[^\s:]+:[^\s:]+(?::[^\s:]+)?:[^\s:]+(?::[^\s:]+)?)")


def validate_maven(graph: DependencyGraph, native: Path) -> bool:
    depths: dict = {}
    for line in native.read_text().splitlines()[1:]:  # first line is the root project
        m = MVN_LINE.match(line)
        if not m:
            continue
        parts = m["coord"].split(":")
        group, artifact = parts[0], parts[1]
        version = parts[3] if len(parts) == 5 else parts[4] if len(parts) == 6 else parts[2]
        scope = parts[-1]
        if scope in {"test", "provided", "system"}:
            continue
        depth = len(m["indent"]) // 3
        key = (f"{group}:{artifact}", version)
        depths[key] = min(depth, depths.get(key, depth))
    return compare_depths("maven (mvn dependency:tree)", sbom_index(graph), depths)


def validate_go(graph: DependencyGraph, native: Path) -> bool:
    decoder, text, pos, mods = json.JSONDecoder(), native.read_text(), 0, []
    while pos < len(text):
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text):
            break
        obj, pos = decoder.raw_decode(text, pos)
        mods.append(obj)
    build_list = {}
    for m in mods:
        if m.get("Main"):
            continue
        replace = m.get("Replace") or {}
        build_list[m["Path"]] = replace.get("Version") or m.get("Version")
        if replace.get("Path"):  # replace directive: the SBOM names the module actually built
            build_list[replace["Path"]] = replace.get("Version") or m.get("Version")
    ours = {(c.purl.coordinate if c.purl else c.name): c.version for c in graph.components.values()}
    missing = sorted(p for p in ours if p not in build_list)
    wrong_version = sorted(p for p in ours if p in build_list and build_list[p] != ours[p])
    print("go (go list -m all)")
    print(f"  build list modules: {len(build_list)}   SBOM modules (linked into binary): {len(ours)}")
    print(f"  SBOM modules found in build list: {len(ours) - len(missing)}   same version: {len(ours) - len(missing) - len(wrong_version)}")
    if missing:
        print("  not in build list: " + ", ".join(missing[:8]))
    if wrong_version:
        print("  version differs: " + ", ".join(f"{p} sbom={ours[p]} go={build_list[p]}" for p in wrong_version[:8]))
    print("  note: Go has no per-module parent tree to compare depth against; versions are checked instead.")
    ok = not missing and not wrong_version
    print(f"  RESULT: {'PASS' if ok else 'CHECK'} (threshold: every SBOM module in the build list at the same version)")
    return ok


def main() -> int:
    if len(sys.argv) != 4 or sys.argv[1] not in {"npm", "pip", "maven", "go"}:
        print(__doc__)
        return 2
    kind, sbom, native = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
    graph = DependencyGraph(parse_file(sbom))
    ok = {"npm": validate_npm, "pip": validate_pip, "maven": validate_maven, "go": validate_go}[kind](graph, native)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
