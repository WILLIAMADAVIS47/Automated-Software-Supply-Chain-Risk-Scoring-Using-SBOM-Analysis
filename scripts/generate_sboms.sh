#!/usr/bin/env bash
# Regenerate the CycloneDX SBOMs for the four test projects (Task C).
# Tool choices: "docs/Task B Tool Selection.docx". Project choices: "docs/Task C Test Projects.docx".
#
# Requirements: git, Node.js 20+ and npm, Go 1.21+, JDK 25 and Maven 3.9+, uv.
# Usage: scripts/generate_sboms.sh [WORK_DIR]   (clones go to WORK_DIR, default ./work)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${1:-$ROOT/work}"
OUT="$ROOT/data/sboms"
mkdir -p "$WORK" "$OUT"

CYCLONEDX_NPM=2.1.0
CYCLONEDX_GOMOD=v1.9.0
CYCLONEDX_MAVEN=2.9.1
CYCLONEDX_PY=5.1.1

clone() {  # clone <github repo> <tag> <dir>
  [ -d "$WORK/$3" ] || git -c advice.detachedHead=false clone -q --depth 1 --branch "$2" "https://github.com/$1" "$WORK/$3"
}

echo "== OWASP Juice Shop v20.2.0 (npm)"
clone juice-shop/juice-shop v20.2.0 juice-shop
(cd "$WORK/juice-shop" \
  && npm install --package-lock-only --ignore-scripts --no-audit --no-fund \
  && npx --yes "@cyclonedx/cyclonedx-npm@$CYCLONEDX_NPM" --package-lock-only --omit dev \
       --spec-version 1.5 --output-format JSON --output-file "$OUT/juice-shop-v20.2.0.cdx.json")

echo "== OWASP PyGoat v2.0.1 (PyPI)"
clone adeyosemanputra/pygoat v2.0.1 pygoat
uv python install 3.9
uv venv -q --allow-existing -p 3.9 "$WORK/pygoat-venv"
VIRTUAL_ENV="$WORK/pygoat-venv" uv pip install -q -r "$WORK/pygoat/requirements.txt"   # psycopg2 needs libpq-dev
uv tool run --from "cyclonedx-bom==$CYCLONEDX_PY" cyclonedx-py environment \
  --sv 1.5 --of JSON -o "$OUT/pygoat-v2.0.1.cdx.json" "$WORK/pygoat-venv"
VIRTUAL_ENV="$WORK/pygoat-venv" uv pip install -q pipdeptree==2.28.0
"$WORK/pygoat-venv/bin/pipdeptree" --json > "$WORK/pygoat-pipdeptree.json"
python3 "$ROOT/scripts/add_root_component.py" "$OUT/pygoat-v2.0.1.cdx.json" \
  "$WORK/pygoat/requirements.txt" pygoat 2.0.1 \
  --also-direct "Django,requests,PyJWT,PyYAML,argon2-cffi,Pillow,django-heroku" \
  --required-edges "$WORK/pygoat-pipdeptree.json"

echo "== OWASP WebGoat v2026.4 (Maven)"
clone WebGoat/WebGoat v2026.4 webgoat
(cd "$WORK/webgoat" \
  && mvn -B -q -Denforcer.skip=true "org.cyclonedx:cyclonedx-maven-plugin:$CYCLONEDX_MAVEN:makeAggregateBom" \
       -DincludeTestScope=false -DincludeProvidedScope=false \
       -DoutputFormat=json -DschemaVersion=1.5 -DoutputName=webgoat.cdx \
  && cp target/webgoat.cdx.json "$OUT/webgoat-v2026.4.cdx.json")

echo "== Gitea v1.21.0 (Go)"
clone go-gitea/gitea v1.21.0 gitea
GOBIN="$WORK/bin" go install "github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@$CYCLONEDX_GOMOD"
(cd "$WORK/gitea" && "$WORK/bin/cyclonedx-gomod" app -json -licenses=false -main . \
  -output "$OUT/gitea-v1.21.0.cdx.json")

echo "== Etherpad 1.8.6 (npm), added Nov 2026 at the advisor's request as a fifth, larger project"
clone ether/etherpad-lite 1.8.6 etherpad
(cd "$WORK/etherpad/src" \
  && npm install --package-lock-only --ignore-scripts --no-audit --no-fund \
  && npx --yes "@cyclonedx/cyclonedx-npm@$CYCLONEDX_NPM" --package-lock-only --omit dev \
       --spec-version 1.5 --output-format JSON --output-file "$OUT/etherpad-v1.8.6.cdx.json")

echo "== Wiki.js v2.5.300 (npm), added Nov 2026 as a sixth, larger project"
clone requarks/wiki v2.5.300 wikijs
# The tag ships a yarn.lock; npm needs --legacy-peer-deps to resolve it, and cyclonedx-npm then reports
# peer-dependency warnings (graphql, mysql2), so the root component is restored by name afterwards.
(cd "$WORK/wikijs" \
  && npm install --package-lock-only --ignore-scripts --no-audit --no-fund --legacy-peer-deps \
  && npx --yes "@cyclonedx/cyclonedx-npm@$CYCLONEDX_NPM" --package-lock-only --omit dev --ignore-npm-errors \
       --spec-version 1.5 --output-format JSON --output-file "$OUT/wikijs-v2.5.300.cdx.json")
python3 - "$OUT/wikijs-v2.5.300.cdx.json" <<'PY'
import json, sys
p = sys.argv[1]
d = json.loads(open(p).read().replace('"DummyComponent.RootComponent"', '"wiki@2.5.300"'))
d["metadata"]["component"].update({"name": "wiki", "version": "2.5.300"})
json.dump(d, open(p, "w"), indent=2)
PY

echo "Done. SBOMs in $OUT"
