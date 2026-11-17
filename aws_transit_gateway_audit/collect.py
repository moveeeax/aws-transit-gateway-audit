"""The only module that talks to AWS. Reads ec2, returns plain dicts.

Everything here is read-only: describe_* and get_* plus
search_transit_gateway_routes. The output is exactly what `--from-json`
consumes, so a recorded payload replays a full audit offline.
"""

from __future__ import annotations

from .model import PAYLOAD_VERSION

# search_transit_gateway_routes needs at least one filter, so ask for every
# state we care about rather than trying to express "match all".
ROUTE_STATES = ["active", "blackhole", "pending"]
ROUTE_PAGE = 1000


class CollectError(RuntimeError):
    """An AWS call that stops the audit."""


def _pages(client, operation: str, key: str, **kwargs) -> list[dict]:
    if client.can_paginate(operation):
        paginator = client.get_paginator(operation)
        out: list[dict] = []
        for page in paginator.paginate(**kwargs):
            out.extend(page.get(key, []))
        return out
    return getattr(client, operation)(**kwargs).get(key, [])


def _session(profile: str | None):
    try:
        import boto3
    except ImportError as exc:  # pragma: no cover - boto3 is a hard dependency
        raise CollectError("boto3 is required for live collection") from exc
    return boto3.Session(profile_name=profile) if profile else boto3.Session()


def collect_region(region: str, profile: str | None = None, client=None) -> dict:
    """Collect one region's Transit Gateway topology."""
    ec2 = client or _session(profile).client("ec2", region_name=region)

    gateways = _pages(ec2, "describe_transit_gateways", "TransitGateways")
    attachments = _pages(ec2, "describe_transit_gateway_attachments", "TransitGatewayAttachments")
    route_tables = _pages(
        ec2, "describe_transit_gateway_route_tables", "TransitGatewayRouteTables"
    )
    vpc_attachments = _pages(
        ec2, "describe_transit_gateway_vpc_attachments", "TransitGatewayVpcAttachments"
    )

    associations: dict[str, list[dict]] = {}
    propagations: dict[str, list[dict]] = {}
    routes: dict[str, list[dict]] = {}
    for table in route_tables:
        table_id = table.get("TransitGatewayRouteTableId")
        if not table_id:
            continue
        associations[table_id] = _pages(
            ec2,
            "get_transit_gateway_route_table_associations",
            "Associations",
            TransitGatewayRouteTableId=table_id,
        )
        propagations[table_id] = _pages(
            ec2,
            "get_transit_gateway_route_table_propagations",
            "TransitGatewayRouteTablePropagations",
            TransitGatewayRouteTableId=table_id,
        )
        found = ec2.search_transit_gateway_routes(
            TransitGatewayRouteTableId=table_id,
            Filters=[{"Name": "state", "Values": ROUTE_STATES}],
            MaxResults=ROUTE_PAGE,
        )
        routes[table_id] = found.get("Routes", [])

    vpc_ids = sorted({a.get("VpcId") for a in vpc_attachments if a.get("VpcId")})
    subnets: list[dict] = []
    vpcs: list[dict] = []
    if vpc_ids:
        vpc_filter = [{"Name": "vpc-id", "Values": vpc_ids}]
        subnets = _pages(ec2, "describe_subnets", "Subnets", Filters=vpc_filter)
        vpcs = _pages(ec2, "describe_vpcs", "Vpcs", VpcIds=vpc_ids)

    return {
        "transit_gateways": gateways,
        "attachments": attachments,
        "route_tables": route_tables,
        "associations": associations,
        "propagations": propagations,
        "routes": routes,
        "vpc_attachments": vpc_attachments,
        "subnets": subnets,
        "vpcs": vpcs,
    }


def collect(regions: list[str], profile: str | None = None) -> dict:
    """Collect several regions into one payload document."""
    from botocore.exceptions import BotoCoreError, ClientError

    out: dict[str, dict] = {}
    for region in regions:
        try:
            out[region] = collect_region(region, profile=profile)
        except (BotoCoreError, ClientError) as exc:
            raise CollectError(f"{region}: {exc}") from exc
    return {"version": PAYLOAD_VERSION, "regions": out}
