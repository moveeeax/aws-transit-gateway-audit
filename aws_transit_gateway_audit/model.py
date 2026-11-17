"""The in-memory topology the rules run against.

A payload is a plain dict so it can come from `collect.py` (boto3) or from a
JSON file recorded earlier with `--dump-json`. Nothing below touches the
network, which is what makes every rule testable from a fixture.
"""

from __future__ import annotations

from dataclasses import dataclass, field

PAYLOAD_VERSION = 1

SEVERITIES = ("ok", "warn", "critical")
_RANK = {name: index for index, name in enumerate(SEVERITIES)}


def worst(*values: str) -> str:
    """Return the highest severity among the arguments."""
    return max((v for v in values if v in _RANK), key=lambda v: _RANK[v], default="ok")


class PayloadError(ValueError):
    """A payload that cannot be read as a topology."""


@dataclass
class Finding:
    rule: str
    severity: str
    scope: str
    target: str
    message: str
    region: str = ""
    gateway: str = ""
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        out = {
            "rule": self.rule,
            "severity": self.severity,
            "scope": self.scope,
            "target": self.target,
            "message": self.message,
            "region": self.region,
            "transit_gateway_id": self.gateway,
        }
        if self.details:
            out["details"] = self.details
        return out


@dataclass
class Topology:
    """One region's Transit Gateway topology plus lookup indexes."""

    region: str
    gateways: list[dict]
    attachments: list[dict]
    route_tables: list[dict]
    associations: dict[str, list[dict]]
    propagations: dict[str, list[dict]]
    routes: dict[str, list[dict]]
    vpc_attachments: list[dict]
    subnets: list[dict]
    vpcs: list[dict]

    # indexes, filled in __post_init__
    attachment_by_id: dict[str, dict] = field(default_factory=dict)
    vpc_attachment_by_id: dict[str, dict] = field(default_factory=dict)
    table_by_id: dict[str, dict] = field(default_factory=dict)
    subnets_by_vpc: dict[str, list[dict]] = field(default_factory=dict)
    vpc_by_id: dict[str, dict] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.attachment_by_id = {
            a["TransitGatewayAttachmentId"]: a
            for a in self.attachments
            if a.get("TransitGatewayAttachmentId")
        }
        self.vpc_attachment_by_id = {
            a["TransitGatewayAttachmentId"]: a
            for a in self.vpc_attachments
            if a.get("TransitGatewayAttachmentId")
        }
        self.table_by_id = {
            t["TransitGatewayRouteTableId"]: t
            for t in self.route_tables
            if t.get("TransitGatewayRouteTableId")
        }
        for subnet in self.subnets:
            self.subnets_by_vpc.setdefault(subnet.get("VpcId", ""), []).append(subnet)
        self.vpc_by_id = {v["VpcId"]: v for v in self.vpcs if v.get("VpcId")}

    # -- relations ---------------------------------------------------------

    def association_table(self, attachment_id: str) -> str | None:
        """Route table an attachment is associated with, or None."""
        for table_id, rows in self.associations.items():
            for row in rows:
                if row.get("TransitGatewayAttachmentId") == attachment_id:
                    if row.get("State") in (None, "associated", "associating"):
                        return table_id
        inline = self.attachment_by_id.get(attachment_id, {}).get("Association") or {}
        return inline.get("TransitGatewayRouteTableId")

    def propagation_tables(self, attachment_id: str) -> list[str]:
        """Route tables an attachment propagates its routes into."""
        out = []
        for table_id, rows in self.propagations.items():
            for row in rows:
                if row.get("TransitGatewayAttachmentId") != attachment_id:
                    continue
                if row.get("State") in (None, "enabled", "enabling"):
                    out.append(table_id)
                    break
        return sorted(out)

    def propagating_attachments(self, table_id: str) -> list[str]:
        return sorted(
            row["TransitGatewayAttachmentId"]
            for row in self.propagations.get(table_id, [])
            if row.get("TransitGatewayAttachmentId")
            and row.get("State") in (None, "enabled", "enabling")
        )

    def route_targets(self) -> set[str]:
        """Every attachment id that is the target of at least one live route."""
        targets: set[str] = set()
        for rows in self.routes.values():
            for route in rows:
                if route.get("State") == "blackhole":
                    continue
                for target in route.get("TransitGatewayAttachments") or []:
                    if target.get("TransitGatewayAttachmentId"):
                        targets.add(target["TransitGatewayAttachmentId"])
        return targets

    def attachment_cidrs(self, attachment_id: str) -> list[str]:
        """CIDRs behind a VPC attachment, resolved from the VPC locally."""
        vpc_attachment = self.vpc_attachment_by_id.get(attachment_id)
        if not vpc_attachment:
            return []
        vpc = self.vpc_by_id.get(vpc_attachment.get("VpcId", ""))
        if not vpc:
            return []
        associated = vpc.get("CidrBlockAssociationSet") or []
        cidrs = [c["CidrBlock"] for c in associated if c.get("CidrBlock")]
        if not cidrs and vpc.get("CidrBlock"):
            cidrs = [vpc["CidrBlock"]]
        return cidrs

    def gateway_attachments(self, gateway_id: str) -> list[dict]:
        return [a for a in self.attachments if a.get("TransitGatewayId") == gateway_id]

    def gateway_tables(self, gateway_id: str) -> list[dict]:
        return [t for t in self.route_tables if t.get("TransitGatewayId") == gateway_id]


def _as_list(payload: dict, key: str) -> list[dict]:
    value = payload.get(key, [])
    if value is None:
        return []
    if not isinstance(value, list):
        raise PayloadError(f"'{key}' must be a list, got {type(value).__name__}")
    return [v for v in value if isinstance(v, dict)]


def _as_map(payload: dict, key: str) -> dict[str, list[dict]]:
    value = payload.get(key, {})
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise PayloadError(f"'{key}' must be an object keyed by route table id")
    return {k: [r for r in (v or []) if isinstance(r, dict)] for k, v in value.items()}


def topology_from_payload(region: str, payload: dict) -> Topology:
    if not isinstance(payload, dict):
        raise PayloadError(f"region '{region}' must map to an object")
    return Topology(
        region=region,
        gateways=_as_list(payload, "transit_gateways"),
        attachments=_as_list(payload, "attachments"),
        route_tables=_as_list(payload, "route_tables"),
        associations=_as_map(payload, "associations"),
        propagations=_as_map(payload, "propagations"),
        routes=_as_map(payload, "routes"),
        vpc_attachments=_as_list(payload, "vpc_attachments"),
        subnets=_as_list(payload, "subnets"),
        vpcs=_as_list(payload, "vpcs"),
    )


def topologies_from_payload(payload: dict) -> list[Topology]:
    """Read a whole `--dump-json` document into one Topology per region."""
    if not isinstance(payload, dict):
        raise PayloadError("payload must be a JSON object")
    regions = payload.get("regions")
    if not isinstance(regions, dict) or not regions:
        raise PayloadError("payload needs a non-empty 'regions' object")
    return [topology_from_payload(name, body) for name, body in sorted(regions.items())]
