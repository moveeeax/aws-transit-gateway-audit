import datetime as dt
import json
from pathlib import Path

import pytest

from aws_transit_gateway_audit.config import Rules
from aws_transit_gateway_audit.model import topologies_from_payload
from aws_transit_gateway_audit.rules import Engine

FIXTURES = Path(__file__).parent / "fixtures"
# Fixed clock so the pendingAcceptance age check is deterministic.
NOW = dt.datetime(2026, 10, 1, 12, 0, tzinfo=dt.UTC)


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture
def broken_payload() -> dict:
    return load("hub_and_spoke.json")


@pytest.fixture
def clean_payload() -> dict:
    return load("clean.json")


@pytest.fixture
def broken_topology(broken_payload):
    return topologies_from_payload(broken_payload)[0]


@pytest.fixture
def clean_topology(clean_payload):
    return topologies_from_payload(clean_payload)[0]


@pytest.fixture
def engine() -> Engine:
    return Engine(rules=Rules(), now=NOW)


@pytest.fixture
def broken_findings(engine, broken_topology):
    return engine.run(broken_topology)


def by_rule(findings, rule):
    return [f for f in findings if f.rule == rule]


def one(findings, rule):
    hits = by_rule(findings, rule)
    assert len(hits) == 1, f"expected exactly one {rule}, got {[f.target for f in hits]}"
    return hits[0]
