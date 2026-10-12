import json
from pathlib import Path

import pytest

from sbomrisk.models import Purl
from sbomrisk.parser import SBOMError, parse_document, parse_file

FIXTURE = Path(__file__).parent / "fixtures" / "small.cdx.json"


def test_parses_root_components_and_nested():
    sbom = parse_file(FIXTURE)
    assert sbom.spec_version == "1.5"
    assert sbom.root.bom_ref == "app"
    assert set(sbom.components) == {"a", "b", "c", "c-nested", "d", "orphan"}


def test_unknown_edge_is_dropped_with_warning():
    sbom = parse_file(FIXTURE)
    assert ("b", "ghost") not in sbom.edges
    assert any("ghost" in w for w in sbom.warnings)


@pytest.mark.parametrize(
    "purl, coordinate, version, ptype",
    [
        ("pkg:npm/%40scope/core@2.0", "@scope/core", "2.0", "npm"),
        ("pkg:maven/org.yaml/snakeyaml@1.33?type=jar", "org.yaml:snakeyaml", "1.33", "maven"),
        ("pkg:golang/golang.org/x/net@v0.17.0?type=module", "golang.org/x/net", "v0.17.0", "golang"),
        ("pkg:pypi/django@4.1.7", "django", "4.1.7", "pypi"),
    ],
)
def test_purl_parse(purl, coordinate, version, ptype):
    p = Purl.parse(purl)
    assert (p.coordinate, p.version, p.type) == (coordinate, version, ptype)


def test_rejects_non_cyclonedx():
    with pytest.raises(SBOMError):
        parse_document({"spdxVersion": "SPDX-2.3"})


def test_rejects_unsupported_spec_version():
    doc = json.loads(FIXTURE.read_text())
    doc["specVersion"] = "1.2"
    with pytest.raises(SBOMError):
        parse_document(doc)
