"""Add a root application component to a CycloneDX SBOM that lacks one (used for PyGoat).

cyclonedx-py's `environment` mode describes an installed virtualenv, so it has no
metadata.component and no record of which packages the application asked for.
It also records edges for optional "extras" (for example Django -> argon2-cffi,
cryptography -> pytz from its test extra) as if they were required.

This script:
1. Optionally drops dependency edges that pip does not consider required, using
   `pipdeptree --json` output from the same virtualenv (--required-edges).
2. Adds the application as the root. Its direct dependencies are the packages in
   the requirements file that no other installed package requires, plus any the
   application imports itself (--also-direct). PyGoat's requirements.txt is a
   full `pip freeze`, so treating every listed package as direct would flatten
   every depth to 1.

Usage:
  python add_root_component.py SBOM.json REQUIREMENTS.txt NAME VERSION
      [--also-direct Django,requests,...] [--required-edges pipdeptree.json]
"""

import argparse
import json
import re
import sys


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("sbom")
    ap.add_argument("requirements")
    ap.add_argument("name")
    ap.add_argument("version")
    ap.add_argument("--also-direct", default="", help="comma-separated distributions the app imports directly")
    ap.add_argument("--required-edges", help="pipdeptree --json output; edges not in it are removed")
    args = ap.parse_args()

    with open(args.sbom, encoding="utf-8") as f:
        doc = json.load(f)
    if (doc.get("metadata") or {}).get("component"):
        sys.exit(f"{args.sbom} already has a root component")

    by_name = {normalize(c["name"]): c["bom-ref"] for c in doc["components"]}
    name_of = {ref: n for n, ref in by_name.items()}

    if args.required_edges:
        with open(args.required_edges, encoding="utf-8") as f:
            required = {
                (normalize(r["package"]["key"]), normalize(d["key"])) for r in json.load(f) for d in r["dependencies"]
            }
        removed = []
        for dep in doc.get("dependencies", []):
            keep = [c for c in dep.get("dependsOn", []) if (name_of.get(dep["ref"]), name_of.get(c)) in required]
            removed += [f"{name_of.get(dep['ref'])}->{name_of.get(c)}" for c in dep.get("dependsOn", []) if c not in keep]
            dep["dependsOn"] = keep
        print(f"removed {len(removed)} optional-extra edges: {', '.join(sorted(removed))}", file=sys.stderr)

    wanted = set()
    for line in open(args.requirements, encoding="utf-8"):
        line = line.split("#", 1)[0].strip()
        if line and not line.startswith("-"):
            wanted.add(normalize(re.split(r"[<>=!~;\[ ]", line, maxsplit=1)[0]))
    missing = sorted(wanted - set(by_name))
    if missing:
        print(f"warning: requirements not found in SBOM: {missing}", file=sys.stderr)

    required_by_others = {child for dep in doc.get("dependencies", []) for child in dep.get("dependsOn", [])}
    imported = {normalize(n) for n in args.also_direct.split(",") if n.strip()}
    direct = sorted(
        by_name[n] for n in wanted if n in by_name and (by_name[n] not in required_by_others or n in imported)
    )

    root_ref = f"{args.name}@{args.version}"
    doc.setdefault("metadata", {})["component"] = {
        "type": "application",
        "bom-ref": root_ref,
        "name": args.name,
        "version": args.version,
    }
    doc.setdefault("dependencies", []).append({"ref": root_ref, "dependsOn": direct})
    with open(args.sbom, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")


if __name__ == "__main__":
    main()
