import json

from aws_transit_gateway_audit.cli import EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main, resolve_regions


def run(capsys, *argv):
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_from_json_replays_offline(capsys, fixtures_dir):
    code, out, err = run(capsys, "--from-json", str(fixtures_dir / "hub_and_spoke.json"))
    assert code == EXIT_FINDINGS
    assert err == ""
    assert "tgw-attachment-unassociated" in out
    assert "11 finding(s): 3 critical, 8 warn" in out


def test_fail_on_critical_is_one_and_clean_is_zero(capsys, fixtures_dir):
    broken, _, _ = run(
        capsys, "--from-json", str(fixtures_dir / "hub_and_spoke.json"), "--fail-on", "critical"
    )
    clean, _, _ = run(
        capsys, "--from-json", str(fixtures_dir / "clean.json"), "--fail-on", "critical"
    )
    assert (broken, clean) == (EXIT_FINDINGS, EXIT_OK)


def test_fail_on_none_always_zero(capsys, fixtures_dir):
    code, _, _ = run(
        capsys, "--from-json", str(fixtures_dir / "hub_and_spoke.json"), "--fail-on", "none"
    )
    assert code == EXIT_OK


def test_fail_on_warn_catches_a_warn_only_run(capsys, fixtures_dir, broken_payload, tmp_path):
    region = broken_payload["regions"]["eu-central-1"]
    region["attachments"] = [a for a in region["attachments"] if a["State"] == "available"]
    region["routes"]["tgw-rtb-shared00000001"] = [
        r
        for r in region["routes"]["tgw-rtb-shared00000001"]
        if r["DestinationCidrBlock"] != "172.16.9.0/24"
    ]
    for attachment in region["attachments"]:
        if attachment["TransitGatewayAttachmentId"] == "tgw-attach-stage00001":
            region["associations"]["tgw-rtb-shared00000001"].append(
                {"TransitGatewayAttachmentId": "tgw-attach-stage00001", "State": "associated"}
            )
    path = tmp_path / "warn-only.json"
    path.write_text(json.dumps(broken_payload))

    warn_code, out, _ = run(capsys, "--from-json", str(path), "--fail-on", "warn")
    critical_code, _, _ = run(capsys, "--from-json", str(path), "--fail-on", "critical")
    assert "0 critical" in out
    assert (warn_code, critical_code) == (EXIT_FINDINGS, EXIT_OK)


def test_json_format_exposes_attachment_severity(capsys, fixtures_dir):
    code, out, _ = run(
        capsys, "--from-json", str(fixtures_dir / "hub_and_spoke.json"), "--format", "json"
    )
    parsed = json.loads(out)
    assert code == EXIT_FINDINGS
    assert parsed["version"] == 1
    assert parsed["regions"] == ["eu-central-1"]
    assert [a["id"] for a in parsed["attachments"] if a["severity"] == "critical"]


def test_markdown_format(capsys, fixtures_dir):
    _, out, _ = run(
        capsys, "--from-json", str(fixtures_dir / "hub_and_spoke.json"), "--format", "markdown"
    )
    assert out.startswith("# Transit Gateway audit")


def test_region_filter_on_a_replayed_payload(capsys, fixtures_dir):
    code, _, err = run(
        capsys,
        "--from-json",
        str(fixtures_dir / "clean.json"),
        "--region",
        "eu-central-1",
    )
    assert code == EXIT_USAGE
    assert "no region matching" in err


def test_region_filter_keeps_a_matching_region(capsys, fixtures_dir):
    code, out, _ = run(
        capsys, "--from-json", str(fixtures_dir / "clean.json"), "--region", "eu-west-1"
    )
    assert code == EXIT_OK
    assert "region eu-west-1" in out


def test_attachment_cost_flag_reaches_the_rule(capsys, fixtures_dir):
    _, out, _ = run(
        capsys,
        "--from-json",
        str(fixtures_dir / "hub_and_spoke.json"),
        "--attachment-monthly-cost",
        "90",
    )
    assert "90.00 USD/month" in out


def test_pending_age_flag_reaches_the_rule(capsys, fixtures_dir):
    _, out, _ = run(
        capsys,
        "--from-json",
        str(fixtures_dir / "hub_and_spoke.json"),
        "--max-pending-age-days",
        "100000",
    )
    assert "tgw-attachment-pending" not in out


def test_rules_file_is_applied(capsys, fixtures_dir, tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text("ignore_rules:\n  - tgw-route-blackhole\nattachment_monthly_cost: 12.5\n")
    _, out, _ = run(
        capsys, "--from-json", str(fixtures_dir / "hub_and_spoke.json"), "--rules", str(path)
    )
    assert "tgw-route-blackhole" not in out
    assert "12.50 USD/month" in out


def test_dump_json_writes_the_payload_back(capsys, fixtures_dir, tmp_path):
    out_path = tmp_path / "dump.json"
    code, _, _ = run(
        capsys,
        "--from-json",
        str(fixtures_dir / "clean.json"),
        "--dump-json",
        str(out_path),
    )
    assert code == EXIT_OK
    assert json.loads(out_path.read_text())["regions"]["eu-west-1"]["attachments"]


def test_no_region_and_no_payload_is_a_usage_error(capsys):
    code, _, err = run(capsys)
    assert code == EXIT_USAGE
    assert "--from-json" in err


def test_malformed_json_exits_two_without_a_traceback(capsys, tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json")
    code, _, err = run(capsys, "--from-json", str(path))
    assert code == EXIT_USAGE
    assert "not valid JSON" in err
    assert "Traceback" not in err


def test_missing_payload_file_exits_two(capsys):
    code, _, err = run(capsys, "--from-json", "/nonexistent/payload.json")
    assert code == EXIT_USAGE
    assert "cannot read" in err


def test_payload_without_regions_exits_two(capsys, tmp_path):
    path = tmp_path / "empty.json"
    path.write_text('{"version": 1, "regions": {}}')
    code, _, err = run(capsys, "--from-json", str(path))
    assert code == EXIT_USAGE
    assert "regions" in err


def test_payload_with_a_wrong_shape_exits_two(capsys, tmp_path):
    path = tmp_path / "weird.json"
    path.write_text('{"regions": {"eu-central-1": {"attachments": "lots"}}}')
    code, _, err = run(capsys, "--from-json", str(path))
    assert code == EXIT_USAGE
    assert "must be a list" in err


def test_bad_rules_file_exits_two(capsys, fixtures_dir, tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text("made_up_key: 1\n")
    code, _, err = run(
        capsys, "--from-json", str(fixtures_dir / "clean.json"), "--rules", str(path)
    )
    assert code == EXIT_USAGE
    assert "unknown rules keys" in err


def test_negative_cost_is_rejected(capsys, fixtures_dir):
    code, _, err = run(
        capsys,
        "--from-json",
        str(fixtures_dir / "clean.json"),
        "--attachment-monthly-cost",
        "-5",
    )
    assert code == EXIT_USAGE
    assert "must not be negative" in err


def test_resolve_regions_dedupes_and_keeps_order():
    class Args:
        region = "eu-central-1"
        regions = "eu-west-1, eu-central-1 ,"

    assert resolve_regions(Args()) == ["eu-central-1", "eu-west-1"]
