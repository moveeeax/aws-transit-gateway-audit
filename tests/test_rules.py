"""Every rule, against the recorded topology. No AWS, no moto."""

import copy
import datetime as dt

from conftest import NOW, by_rule, one

from aws_transit_gateway_audit.config import Rules
from aws_transit_gateway_audit.model import topologies_from_payload, worst
from aws_transit_gateway_audit.rules import RULE_HELP, Engine

STAGE = "tgw-attach-stage00001"
PROD = "tgw-attach-prod000001"
DMZ = "tgw-attach-dmz000001"
LEGACY = "tgw-attach-legacy0001"
LAB = "tgw-attach-lab000001"
SHARED = "tgw-rtb-shared00000001"
ISOLATED = "tgw-rtb-isolated000001"
DEAD = "tgw-rtb-dead0000000001"


def test_clean_topology_has_no_findings(engine, clean_topology):
    assert engine.run(clean_topology) == []


def test_unassociated_attachment_is_critical(broken_findings):
    finding = one(broken_findings, "tgw-attachment-unassociated")
    assert finding.severity == "critical"
    assert finding.target == STAGE
    # the finding names the attachment and the resource behind it
    assert STAGE in finding.message
    assert "vpc-stage00000000001" in finding.message
    assert finding.details["resource_id"] == "vpc-stage00000000001"


def test_blackhole_route_is_warn_with_cidr_and_table(broken_findings):
    finding = one(broken_findings, "tgw-route-blackhole")
    assert finding.severity == "warn"
    assert finding.target == SHARED
    assert "192.168.100.0/24" in finding.message
    assert SHARED in finding.message


def test_overlapping_attachment_cidrs_name_both_sides(broken_findings):
    finding = one(broken_findings, "tgw-attachment-cidr-overlap")
    assert finding.severity == "warn"
    assert {finding.target, finding.details["other_attachment_id"]} == {STAGE, LAB}
    assert finding.details["overlapping_prefixes"] == ["10.20.16.0/20"]
    assert "10.20.16.0/20" in finding.message


def test_az_gap_names_the_missing_zone(broken_findings):
    finding = one(broken_findings, "tgw-attachment-az-gap")
    assert finding.severity == "warn"
    assert finding.target == PROD
    assert finding.details["missing_zones"] == ["eu-central-1c"]
    assert "eu-central-1c" in finding.message


def test_one_way_reachability_names_both_tables(broken_findings):
    finding = one(broken_findings, "tgw-attachment-one-way")
    assert finding.target == DMZ
    assert finding.details["association_route_table"] == ISOLATED
    assert finding.details["propagation_route_table"] == SHARED


def test_dangling_static_route_target_is_critical(broken_findings):
    finding = one(broken_findings, "tgw-route-dangling-target")
    assert finding.severity == "critical"
    assert finding.details["destination_cidr"] == "172.16.9.0/24"
    assert finding.details["attachment_state"] == "missing"


def test_dead_route_table_is_warn(broken_findings):
    finding = one(broken_findings, "tgw-route-table-dead")
    assert finding.target == DEAD


def test_failed_attachment_is_critical(broken_findings):
    finding = one(broken_findings, "tgw-attachment-failed")
    assert finding.severity == "critical"
    assert finding.target == "tgw-attach-oops00001"


def test_pending_attachment_uses_the_age_threshold(broken_topology):
    stale = Engine(rules=Rules(), now=NOW).run(broken_topology)
    assert one(stale, "tgw-attachment-pending").details["age_days"] == 30

    fresh = Engine(rules=Rules(), now=dt.datetime(2026, 9, 3, tzinfo=dt.UTC)).run(
        broken_topology
    )
    assert by_rule(fresh, "tgw-attachment-pending") == []


def test_idle_attachment_prints_the_configured_cost(broken_topology):
    findings = Engine(rules=Rules(attachment_monthly_cost=72.0), now=NOW).run(broken_topology)
    finding = one(findings, "tgw-attachment-idle")
    assert finding.target == LEGACY
    assert finding.details["monthly_cost"] == 72.0
    assert "72.00 USD/month" in finding.message


def test_no_propagation_is_reported_for_the_vpn(broken_findings):
    assert one(broken_findings, "tgw-attachment-no-propagation").target == LEGACY


def test_expected_finding_set(broken_findings):
    counts = {}
    for finding in broken_findings:
        counts[finding.rule] = counts.get(finding.rule, 0) + 1
    assert counts == {
        "tgw-attachment-unassociated": 1,
        "tgw-attachment-no-propagation": 1,
        "tgw-attachment-one-way": 1,
        "tgw-attachment-failed": 1,
        "tgw-attachment-pending": 1,
        "tgw-attachment-az-gap": 1,
        "tgw-attachment-cidr-overlap": 1,
        "tgw-attachment-idle": 1,
        "tgw-route-blackhole": 1,
        "tgw-route-dangling-target": 1,
        "tgw-route-table-dead": 1,
    }
    assert set(counts) <= set(RULE_HELP)


def test_ignore_rules_and_attachments(broken_topology):
    rules = Rules(
        ignore_rules=("tgw-route-blackhole",),
        ignore_attachments=(STAGE,),
    )
    findings = Engine(rules=rules, now=NOW).run(broken_topology)
    assert by_rule(findings, "tgw-route-blackhole") == []
    assert by_rule(findings, "tgw-attachment-unassociated") == []
    # the overlap rule needed the ignored attachment, so it goes quiet too
    assert by_rule(findings, "tgw-attachment-cidr-overlap") == []
    # unrelated findings survive
    assert by_rule(findings, "tgw-attachment-failed")


def test_severity_override_downgrades_a_rule(broken_topology):
    rules = Rules(severity_overrides={"tgw-attachment-unassociated": "warn"})
    findings = Engine(rules=rules, now=NOW).run(broken_topology)
    assert one(findings, "tgw-attachment-unassociated").severity == "warn"


def test_deleting_attachment_is_not_audited_but_breaks_its_route(broken_payload):
    payload = copy.deepcopy(broken_payload)
    region = payload["regions"]["eu-central-1"]
    for attachment in region["attachments"]:
        if attachment["TransitGatewayAttachmentId"] == DMZ:
            attachment["State"] = "deleting"
    region["routes"][ISOLATED][0]["Type"] = "static"

    findings = Engine(rules=Rules(), now=NOW).run(topologies_from_payload(payload)[0])
    assert [f.target for f in by_rule(findings, "tgw-attachment-one-way")] == []
    dangling = [f for f in by_rule(findings, "tgw-route-dangling-target") if f.target == ISOLATED]
    assert dangling and dangling[0].details["attachment_state"] == "deleting"


def test_inline_association_is_honoured(broken_payload):
    """describe_transit_gateway_attachments carries Association inline."""
    payload = copy.deepcopy(broken_payload)
    region = payload["regions"]["eu-central-1"]
    region["associations"] = {}
    for attachment in region["attachments"]:
        if attachment["TransitGatewayAttachmentId"] == PROD:
            attachment["Association"] = {
                "TransitGatewayRouteTableId": SHARED,
                "State": "associated",
            }
    topo = topologies_from_payload(payload)[0]
    assert topo.association_table(PROD) == SHARED


def test_worst_severity():
    assert worst("ok", "warn", "critical") == "critical"
    assert worst("ok", "warn") == "warn"
    assert worst() == "ok"
    assert worst("nonsense") == "ok"
