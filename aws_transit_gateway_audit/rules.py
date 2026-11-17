"""The rule engine: a Topology in, a list of Findings out.

Every rule is a plain function over the local model. No rule calls AWS, so the
whole suite runs against JSON fixtures.
"""

from __future__ import annotations

import datetime as dt
from itertools import combinations

from .config import FAILED_STATES, GONE_STATES, Rules
from .model import Finding, Topology
from .netutil import overlap

LIVE_ATTACHMENT_STATES = ("available", "modifying")

RULE_HELP = {
    "tgw-attachment-unassociated": "available attachment associated with no route table",
    "tgw-attachment-no-propagation": "attachment propagates its routes into no route table",
    "tgw-attachment-one-way": "association table learns nothing from the other spokes",
    "tgw-attachment-failed": "attachment in a failed or rejected state",
    "tgw-attachment-pending": "attachment stuck in pendingAcceptance",
    "tgw-attachment-az-gap": "VPC attachment misses an availability zone the VPC uses",
    "tgw-attachment-cidr-overlap": "two attachments advertise overlapping CIDRs",
    "tgw-attachment-idle": "attachment billed hourly while routing nothing",
    "tgw-route-blackhole": "route discards traffic for its prefix",
    "tgw-route-dangling-target": "route points at an attachment that is going away",
    "tgw-route-table-dead": "route table with no associations and no propagations",
}


def _parse_time(value) -> dt.datetime | None:
    if isinstance(value, dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=dt.UTC)
    if not isinstance(value, str) or not value:
        return None
    text = value.replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.UTC)


def _label(attachment: dict) -> str:
    resource = attachment.get("ResourceId") or "unknown resource"
    kind = attachment.get("ResourceType") or "attachment"
    return f"{kind} {resource}"


class Engine:
    """Runs every rule over one region and collects the findings."""

    def __init__(self, rules: Rules | None = None, now: dt.datetime | None = None):
        self.rules = rules or Rules()
        self.now = now or dt.datetime.now(dt.UTC)

    def run(self, topo: Topology) -> list[Finding]:
        findings: list[Finding] = []
        for check in (
            self._attachment_wiring,
            self._attachment_health,
            self._attachment_overlap,
            self._attachment_waste,
            self._routes,
            self._route_tables,
        ):
            findings.extend(check(topo))
        return [f for f in findings if not self.rules.skips(f.rule)]

    # -- helpers -----------------------------------------------------------

    def _finding(self, rule, default_severity, scope, target, message, topo, gateway, **details):
        return Finding(
            rule=rule,
            severity=self.rules.severity(rule, default_severity),
            scope=scope,
            target=target,
            message=message,
            region=topo.region,
            gateway=gateway,
            details=details,
        )

    def _auditable(self, topo: Topology) -> list[dict]:
        return [
            a
            for a in topo.attachments
            if a.get("TransitGatewayAttachmentId")
            and not self.rules.skips_attachment(a["TransitGatewayAttachmentId"])
            and a.get("State") not in GONE_STATES
        ]

    # -- wiring ------------------------------------------------------------

    def _attachment_wiring(self, topo: Topology) -> list[Finding]:
        out: list[Finding] = []
        for attachment in self._auditable(topo):
            att_id = attachment["TransitGatewayAttachmentId"]
            gateway = attachment.get("TransitGatewayId", "")
            live = attachment.get("State") in LIVE_ATTACHMENT_STATES
            association = topo.association_table(att_id)
            propagations = topo.propagation_tables(att_id)

            if live and not association:
                out.append(
                    self._finding(
                        "tgw-attachment-unassociated",
                        "critical",
                        "attachment",
                        att_id,
                        f"{att_id} ({_label(attachment)}) is available but associated with no "
                        "route table, so it sends nothing and is still billed",
                        topo,
                        gateway,
                        resource_id=attachment.get("ResourceId"),
                        resource_type=attachment.get("ResourceType"),
                    )
                )

            if live and not propagations:
                out.append(
                    self._finding(
                        "tgw-attachment-no-propagation",
                        "warn",
                        "attachment",
                        att_id,
                        f"{att_id} ({_label(attachment)}) propagates its routes into no route "
                        "table, so no spoke learns its prefixes",
                        topo,
                        gateway,
                        resource_id=attachment.get("ResourceId"),
                    )
                )

            if live and association:
                out.extend(self._one_way(topo, attachment, association))
        return out

    def _one_way(self, topo: Topology, attachment: dict, association: str) -> list[Finding]:
        """Association and propagation that point at different tables.

        The attachment is associated with table A, so A is the only table it
        consults when sending. If nothing else propagates into A while other
        spokes do propagate into some table B, this attachment can be reached
        but cannot reach back.
        """
        att_id = attachment["TransitGatewayAttachmentId"]
        gateway = attachment.get("TransitGatewayId", "")
        peers = [
            a["TransitGatewayAttachmentId"]
            for a in topo.gateway_attachments(gateway)
            if a.get("TransitGatewayAttachmentId")
            and a["TransitGatewayAttachmentId"] != att_id
            and a.get("State") not in GONE_STATES
        ]
        if not peers:
            return []
        into_association = [p for p in peers if p in topo.propagating_attachments(association)]
        if into_association:
            return []

        elsewhere = {}
        for table in topo.gateway_tables(gateway):
            table_id = table["TransitGatewayRouteTableId"]
            if table_id == association:
                continue
            reaching = [p for p in peers if p in topo.propagating_attachments(table_id)]
            if reaching:
                elsewhere[table_id] = reaching
        if not elsewhere:
            return []

        other_table, reaching = sorted(elsewhere.items())[0]
        static_targets = {
            target.get("TransitGatewayAttachmentId")
            for route in topo.routes.get(association, [])
            if route.get("State") != "blackhole"
            for target in route.get("TransitGatewayAttachments") or []
        }
        if any(peer in static_targets for peer in peers):
            return []

        return [
            self._finding(
                "tgw-attachment-one-way",
                "warn",
                "attachment",
                att_id,
                f"{att_id} ({_label(attachment)}) is associated with {association}, which no other "
                f"spoke propagates into, while {len(reaching)} attachment(s) propagate into "
                f"{other_table}: reachability is one-way",
                topo,
                gateway,
                association_route_table=association,
                propagation_route_table=other_table,
                peers_propagating_elsewhere=reaching,
            )
        ]

    # -- attachment health -------------------------------------------------

    def _attachment_health(self, topo: Topology) -> list[Finding]:
        out: list[Finding] = []
        for attachment in self._auditable(topo):
            att_id = attachment["TransitGatewayAttachmentId"]
            gateway = attachment.get("TransitGatewayId", "")
            state = (attachment.get("State") or "").lower()

            if state in FAILED_STATES:
                out.append(
                    self._finding(
                        "tgw-attachment-failed",
                        "critical",
                        "attachment",
                        att_id,
                        f"{att_id} ({_label(attachment)}) is in state "
                        f"{attachment.get('State')} and carries no traffic",
                        topo,
                        gateway,
                        state=attachment.get("State"),
                    )
                )

            if state == "pendingacceptance":
                created = _parse_time(attachment.get("CreationTime"))
                age = (self.now - created).days if created else None
                if age is None or age >= self.rules.max_pending_age_days:
                    age_text = f"{age} days" if age is not None else "an unknown time"
                    out.append(
                        self._finding(
                            "tgw-attachment-pending",
                            "warn",
                            "attachment",
                            att_id,
                            f"{att_id} ({_label(attachment)}) has been pendingAcceptance for "
                            f"{age_text}; accept it or delete it",
                            topo,
                            gateway,
                            age_days=age,
                            threshold_days=self.rules.max_pending_age_days,
                        )
                    )

            out.extend(self._az_gap(topo, attachment))
        return out

    def _az_gap(self, topo: Topology, attachment: dict) -> list[Finding]:
        att_id = attachment["TransitGatewayAttachmentId"]
        vpc_attachment = topo.vpc_attachment_by_id.get(att_id)
        if not vpc_attachment:
            return []
        vpc_id = vpc_attachment.get("VpcId", "")
        subnet_ids = set(vpc_attachment.get("SubnetIds") or [])
        if not subnet_ids:
            return []

        vpc_subnets = topo.subnets_by_vpc.get(vpc_id, [])
        if not vpc_subnets:
            return []
        vpc_zones = {s["AvailabilityZone"] for s in vpc_subnets if s.get("AvailabilityZone")}
        attached_zones = {
            s["AvailabilityZone"]
            for s in vpc_subnets
            if s.get("SubnetId") in subnet_ids and s.get("AvailabilityZone")
        }
        missing = sorted(vpc_zones - attached_zones)
        if not missing:
            return []
        subject = "that zone" if len(missing) == 1 else "those zones"
        return [
            self._finding(
                "tgw-attachment-az-gap",
                "warn",
                "attachment",
                att_id,
                f"{att_id} ({_label(attachment)}) has no subnet in {', '.join(missing)}, so "
                f"traffic from {subject} in {vpc_id} is dropped with no error",
                topo,
                attachment.get("TransitGatewayId", ""),
                vpc_id=vpc_id,
                missing_zones=missing,
                attached_zones=sorted(attached_zones),
            )
        ]

    # -- overlap -----------------------------------------------------------

    def _attachment_overlap(self, topo: Topology) -> list[Finding]:
        out: list[Finding] = []
        candidates = [
            a
            for a in self._auditable(topo)
            if a["TransitGatewayAttachmentId"] in topo.vpc_attachment_by_id
        ]
        for left, right in combinations(candidates, 2):
            if left.get("TransitGatewayId") != right.get("TransitGatewayId"):
                continue
            left_id = left["TransitGatewayAttachmentId"]
            right_id = right["TransitGatewayAttachmentId"]
            hits = sorted(
                {
                    prefix
                    for a in topo.attachment_cidrs(left_id)
                    for b in topo.attachment_cidrs(right_id)
                    if (prefix := overlap(a, b))
                }
            )
            if not hits:
                continue
            out.append(
                self._finding(
                    "tgw-attachment-cidr-overlap",
                    "warn",
                    "attachment",
                    left_id,
                    f"{left_id} and {right_id} both advertise {', '.join(hits)}; the longest "
                    "prefix wins and the loser is unreachable through the gateway",
                    topo,
                    left.get("TransitGatewayId", ""),
                    other_attachment_id=right_id,
                    overlapping_prefixes=hits,
                )
            )
        return out

    # -- waste -------------------------------------------------------------

    def _attachment_waste(self, topo: Topology) -> list[Finding]:
        out: list[Finding] = []
        targets = topo.route_targets()
        for attachment in self._auditable(topo):
            att_id = attachment["TransitGatewayAttachmentId"]
            if attachment.get("State") not in LIVE_ATTACHMENT_STATES:
                continue
            if not topo.association_table(att_id):
                continue  # already reported as unassociated
            if topo.propagation_tables(att_id) or att_id in targets:
                continue
            cost = self.rules.attachment_monthly_cost
            out.append(
                self._finding(
                    "tgw-attachment-idle",
                    "warn",
                    "attachment",
                    att_id,
                    f"{att_id} ({_label(attachment)}) propagates nowhere and is the target of no "
                    f"route: it costs about {cost:.2f} USD/month to route nothing",
                    topo,
                    attachment.get("TransitGatewayId", ""),
                    monthly_cost=round(cost, 2),
                )
            )
        return out

    # -- routes ------------------------------------------------------------

    def _routes(self, topo: Topology) -> list[Finding]:
        out: list[Finding] = []
        for table_id, routes in sorted(topo.routes.items()):
            gateway = topo.table_by_id.get(table_id, {}).get("TransitGatewayId", "")
            for route in routes:
                cidr = route.get("DestinationCidrBlock", "?")
                if route.get("State") == "blackhole":
                    out.append(
                        self._finding(
                            "tgw-route-blackhole",
                            "warn",
                            "route_table",
                            table_id,
                            f"{table_id} blackholes {cidr}: traffic for that prefix is dropped "
                            "silently",
                            topo,
                            gateway,
                            destination_cidr=cidr,
                            route_type=route.get("Type"),
                        )
                    )
                    continue
                for target in route.get("TransitGatewayAttachments") or []:
                    att_id = target.get("TransitGatewayAttachmentId")
                    if not att_id:
                        continue
                    known = topo.attachment_by_id.get(att_id)
                    if known is not None and known.get("State") not in GONE_STATES:
                        continue
                    state = known.get("State") if known else "missing"
                    out.append(
                        self._finding(
                            "tgw-route-dangling-target",
                            "critical",
                            "route_table",
                            table_id,
                            f"{table_id} routes {cidr} to {att_id}, which is {state}: the prefix "
                            "resolves to nothing",
                            topo,
                            gateway,
                            destination_cidr=cidr,
                            attachment_id=att_id,
                            attachment_state=state,
                        )
                    )
        return out

    def _route_tables(self, topo: Topology) -> list[Finding]:
        out: list[Finding] = []
        for table in topo.route_tables:
            table_id = table.get("TransitGatewayRouteTableId")
            if not table_id or table.get("State") in GONE_STATES:
                continue
            if topo.associations.get(table_id) or topo.propagations.get(table_id):
                continue
            out.append(
                self._finding(
                    "tgw-route-table-dead",
                    "warn",
                    "route_table",
                    table_id,
                    f"{table_id} has no associations and no propagations: dead configuration "
                    "that still reads like a routing domain",
                    topo,
                    table.get("TransitGatewayId", ""),
                    default_association=bool(table.get("DefaultAssociationRouteTable")),
                )
            )
        return out
