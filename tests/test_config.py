import pytest

from aws_transit_gateway_audit.config import (
    DEFAULT_ATTACHMENT_MONTHLY_COST,
    Rules,
    RulesError,
    load_rules,
    rules_from_dict,
)


def test_defaults():
    rules = rules_from_dict(None)
    assert rules.attachment_monthly_cost == DEFAULT_ATTACHMENT_MONTHLY_COST
    assert rules.max_pending_age_days == 7
    assert not rules.skips("tgw-route-blackhole")


def test_overrides_are_read():
    rules = rules_from_dict(
        {
            "attachment_monthly_cost": 42,
            "max_pending_age_days": 1,
            "ignore_rules": ["tgw-attachment-idle"],
            "ignore_attachments": ["tgw-attach-lab000001"],
            "severity_overrides": {"tgw-route-blackhole": "critical"},
        }
    )
    assert rules.attachment_monthly_cost == 42.0
    assert rules.max_pending_age_days == 1
    assert rules.skips("tgw-attachment-idle")
    assert rules.skips_attachment("tgw-attach-lab000001")
    assert rules.severity("tgw-route-blackhole", "warn") == "critical"
    assert rules.severity("tgw-attachment-az-gap", "warn") == "warn"


@pytest.mark.parametrize(
    "data",
    [
        "a string",
        {"nope": 1},
        {"attachment_monthly_cost": "free"},
        {"attachment_monthly_cost": -1},
        {"max_pending_age_days": -3},
        {"ignore_rules": "tgw-attachment-idle"},
        {"ignore_rules": [1, 2]},
        {"severity_overrides": ["tgw-route-blackhole"]},
        {"severity_overrides": {"tgw-route-blackhole": "loud"}},
    ],
)
def test_bad_rules_raise(data):
    with pytest.raises(RulesError):
        rules_from_dict(data)


def test_load_rules_from_file(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text("attachment_monthly_cost: 50\nignore_rules:\n  - tgw-route-blackhole\n")
    rules = load_rules(str(path))
    assert rules.attachment_monthly_cost == 50.0
    assert rules.skips("tgw-route-blackhole")


def test_load_rules_missing_file():
    with pytest.raises(RulesError):
        load_rules("/nonexistent/rules.yaml")


def test_load_rules_invalid_yaml(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text("attachment_monthly_cost: [unclosed\n")
    with pytest.raises(RulesError):
        load_rules(str(path))


def test_load_rules_without_path_is_defaults():
    assert load_rules(None) == Rules()
