import json

from aws_transit_gateway_audit.report import build_report, render


def report_for(engine, topology):
    return build_report([(topology, engine.run(topology))])


def test_summary_counts(engine, broken_topology):
    report = report_for(engine, broken_topology)
    summary = report["summary"]
    assert summary["critical"] == 3
    assert summary["warn"] == 8
    assert summary["findings"] == 11
    assert summary["severity"] == "critical"
    assert summary["attachments"] == 7
    assert summary["route_tables"] == 3


def test_clean_report_is_ok(engine, clean_topology):
    report = report_for(engine, clean_topology)
    assert report["summary"]["severity"] == "ok"
    assert report["findings"] == []
    assert all(a["severity"] == "ok" for a in report["attachments"])
    assert "No findings." in render(report, "markdown")


def test_attachment_entity_carries_relations(engine, broken_topology):
    report = report_for(engine, broken_topology)
    stage = next(a for a in report["attachments"] if a["id"] == "tgw-attach-stage00001")
    assert stage["severity"] == "critical"
    assert stage["association_route_table"] is None
    assert stage["propagation_route_tables"] == ["tgw-rtb-shared00000001"]
    assert stage["region"] == "eu-central-1"


def test_gateway_severity_rolls_up_children(engine, broken_topology):
    report = report_for(engine, broken_topology)
    gateway = report["gateways"][0]
    assert gateway["severity"] == "critical"
    assert gateway["attachments"] == 7
    assert gateway["route_tables"] == 3


def test_json_render_is_parseable_and_filterable(engine, broken_topology):
    report = report_for(engine, broken_topology)
    parsed = json.loads(render(report, "json"))
    criticals = [a["id"] for a in parsed["attachments"] if a["severity"] == "critical"]
    assert criticals == ["tgw-attach-stage00001", "tgw-attach-oops00001"]


def test_text_render_mentions_every_finding(engine, broken_topology):
    report = report_for(engine, broken_topology)
    text = render(report, "text")
    assert "region eu-central-1" in text
    assert "transit gateway tgw-0hub0000000000001 (core hub)" in text
    for finding in report["findings"]:
        assert finding["rule"] in text
    assert "11 finding(s): 3 critical, 8 warn" in text


def test_markdown_render_sorts_critical_first(engine, broken_topology):
    report = report_for(engine, broken_topology)
    lines = render(report, "markdown").splitlines()
    rows = [line for line in lines if "| `tgw-" in line]
    assert len(rows) == 11
    assert all(row.startswith("| critical") for row in rows[:3])
    assert "# Transit Gateway audit" in lines[0]
