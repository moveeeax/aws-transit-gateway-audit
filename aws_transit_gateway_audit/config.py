"""Tunable thresholds and cost constants, overridable with `--rules file.yaml`."""

from __future__ import annotations

from dataclasses import dataclass, field

# A Transit Gateway attachment is billed per hour whether or not it routes
# anything. 36.50 is the usual list price of 0.05 USD/hour over 730 hours;
# regions differ, so treat it as a placeholder and pass the real number.
DEFAULT_ATTACHMENT_MONTHLY_COST = 36.50

FAILED_STATES = ("failed", "failing", "rejected", "rejecting")
GONE_STATES = ("deleted", "deleting")


class RulesError(ValueError):
    """An unusable `--rules` document."""


@dataclass
class Rules:
    attachment_monthly_cost: float = DEFAULT_ATTACHMENT_MONTHLY_COST
    max_pending_age_days: int = 7
    ignore_rules: tuple[str, ...] = ()
    ignore_attachments: tuple[str, ...] = ()
    severity_overrides: dict[str, str] = field(default_factory=dict)

    def severity(self, rule: str, default: str) -> str:
        return self.severity_overrides.get(rule, default)

    def skips(self, rule: str) -> bool:
        return rule in self.ignore_rules

    def skips_attachment(self, attachment_id: str) -> bool:
        return attachment_id in self.ignore_attachments


_NUMBERS = {
    "attachment_monthly_cost": float,
    "max_pending_age_days": int,
}
_LISTS = ("ignore_rules", "ignore_attachments")


def rules_from_dict(data: dict | None) -> Rules:
    """Build a Rules from a parsed YAML document. Unknown keys are an error."""
    if data is None:
        return Rules()
    if not isinstance(data, dict):
        raise RulesError("rules file must be a YAML mapping")

    known = set(_NUMBERS) | set(_LISTS) | {"severity_overrides"}
    unknown = sorted(set(data) - known)
    if unknown:
        raise RulesError(f"unknown rules keys: {', '.join(unknown)}")

    kwargs: dict = {}
    for key, cast in _NUMBERS.items():
        if key in data:
            try:
                kwargs[key] = cast(data[key])
            except (TypeError, ValueError) as exc:
                raise RulesError(f"'{key}' must be a number: {exc}") from exc
            if kwargs[key] < 0:
                raise RulesError(f"'{key}' must not be negative")

    for key in _LISTS:
        if key in data:
            value = data[key]
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise RulesError(f"'{key}' must be a list of strings")
            kwargs[key] = tuple(value)

    overrides = data.get("severity_overrides") or {}
    if not isinstance(overrides, dict):
        raise RulesError("'severity_overrides' must be a mapping of rule -> severity")
    for rule, severity in overrides.items():
        if severity not in ("ok", "warn", "critical"):
            raise RulesError(f"severity for '{rule}' must be ok, warn or critical")
    kwargs["severity_overrides"] = dict(overrides)

    return Rules(**kwargs)


def load_rules(path: str | None) -> Rules:
    """Read a rules file. Requires PyYAML only when a path is given."""
    if not path:
        return Rules()
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise RulesError(f"cannot read rules file {path}: {exc.strerror}") from exc
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - PyYAML is a hard dependency
        raise RulesError("--rules needs PyYAML installed") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise RulesError(f"{path} is not valid YAML: {exc}") from exc
    return rules_from_dict(data)
