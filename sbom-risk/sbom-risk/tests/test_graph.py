import json
from pathlib import Path

import pytest

from sbomrisk.graph import SYNTHETIC_ROOT, DependencyGraph
from sbomrisk.parser import parse_document, parse_file

FIXTURES = Path(__file__).parent / "fixtures"
DATA = Path(__file__).parents[1] / "data" / "sboms"


def test_depth_is_shortest_path():
    g = DependencyGraph(parse_file(FIXTURES / "small.cdx.json"))
    depths = {ref: c.depth for ref, c in g.components.items()}
    # b is reachable directly and via a; shortest path wins
    assert depths == {"a": 1, "b": 1, "c": 2, "d": 3, "c-nested": 3, "orphan": None}


def test_cycles_and_unreachable_are_reported():
    g = DependencyGraph(parse_file(FIXTURES / "small.cdx.json"))
    stats = g.stats()
    assert stats.has_cycles  # a -> c -> d -> a
    assert stats.unreachable == 1
    assert stats.max_depth == 3


def test_path_to():
    g = DependencyGraph(parse_file(FIXTURES / "small.cdx.json"))
    assert g.path_to("d") == ["a", "c", "d"]
    assert g.path_to("orphan") == []


def test_synthetic_root_when_metadata_component_missing():
    doc = json.loads((FIXTURES / "small.cdx.json").read_text())
    del doc["metadata"]["component"]
    doc["dependencies"] = [d for d in doc["dependencies"] if d["ref"] != "app"]
    g = DependencyGraph(parse_document(doc))
    assert g.synthetic_root and g.root_ref == SYNTHETIC_ROOT
    # only orphan has no parents; a, c, d form a cycle (and b hangs off a), so nothing enters them
    assert g.root_children == {"orphan"}
    assert {ref for ref, c in g.components.items() if c.depth is None} == {"a", "b", "c", "c-nested", "d"}


@pytest.mark.parametrize("sbom", sorted(DATA.glob("*.cdx.json")), ids=lambda p: p.name)
def test_real_sboms_parse_with_root_and_full_reachability(sbom):
    g = DependencyGraph(parse_file(sbom))
    stats = g.stats()
    assert not g.synthetic_root
    assert stats.components > 0 and stats.direct > 0
    assert stats.unreachable == 0
    assert g.sbom.warnings == []
