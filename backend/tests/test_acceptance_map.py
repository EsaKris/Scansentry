"""docs/ACCEPTANCE.md maps each PRD scenario to tests. Fail if the map drifts: a scenario missing, or a referenced test that no longer exists."""
import re
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
DOC = (BACKEND / "docs" / "ACCEPTANCE.md").read_text()
REFS = re.findall(r"`(tests/[\w]+\.py)::(\w+)`", DOC)


def test_all_23_scenarios_are_listed():
    numbers = [int(m) for m in re.findall(r"^\| (\d+) \|", DOC, flags=re.M)]
    assert numbers == list(range(1, 24))


def test_every_referenced_test_exists():
    assert len(REFS) >= 40
    missing = [f"{f}::{n}" for f, n in REFS if not re.search(rf"^def {n}\(", (BACKEND / f).read_text(), flags=re.M)]
    assert not missing, missing


def test_every_scenario_cites_at_least_one_test():
    for row in re.findall(r"^\| \d+ \|.*$", DOC, flags=re.M):
        assert "`tests/" in row, row[:60]
