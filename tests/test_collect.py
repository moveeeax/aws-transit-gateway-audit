"""The collector is shaped so a fake ec2 client is enough to test it."""

from aws_transit_gateway_audit.collect import collect_region
from aws_transit_gateway_audit.model import topologies_from_payload


class FakeEc2:
    """Answers the handful of ec2 calls the collector makes."""

    def __init__(self):
        self.calls = []

    def can_paginate(self, operation):
        return False

    def describe_transit_gateways(self, **kwargs):
        self.calls.append("describe_transit_gateways")
        return {
            "TransitGateways": [
                {"TransitGatewayId": "tgw-0fake000000001", "State": "available"}
            ]
        }

    def describe_transit_gateway_attachments(self, **kwargs):
        return {
            "TransitGatewayAttachments": [
                {
                    "TransitGatewayAttachmentId": "tgw-attach-fake00001",
                    "TransitGatewayId": "tgw-0fake000000001",
                    "ResourceType": "vpc",
                    "ResourceId": "vpc-fake000000001",
                    "State": "available",
                }
            ]
        }

    def describe_transit_gateway_route_tables(self, **kwargs):
        return {
            "TransitGatewayRouteTables": [
                {
                    "TransitGatewayRouteTableId": "tgw-rtb-fake000001",
                    "TransitGatewayId": "tgw-0fake000000001",
                    "State": "available",
                }
            ]
        }

    def describe_transit_gateway_vpc_attachments(self, **kwargs):
        return {
            "TransitGatewayVpcAttachments": [
                {
                    "TransitGatewayAttachmentId": "tgw-attach-fake00001",
                    "VpcId": "vpc-fake000000001",
                    "SubnetIds": ["subnet-fake0a00001"],
                    "State": "available",
                }
            ]
        }

    def get_transit_gateway_route_table_associations(self, **kwargs):
        self.calls.append(("associations", kwargs["TransitGatewayRouteTableId"]))
        return {
            "Associations": [
                {"TransitGatewayAttachmentId": "tgw-attach-fake00001", "State": "associated"}
            ]
        }

    def get_transit_gateway_route_table_propagations(self, **kwargs):
        return {
            "TransitGatewayRouteTablePropagations": [
                {"TransitGatewayAttachmentId": "tgw-attach-fake00001", "State": "enabled"}
            ]
        }

    def search_transit_gateway_routes(self, **kwargs):
        self.calls.append(("routes", kwargs["Filters"][0]["Values"]))
        return {
            "Routes": [
                {
                    "DestinationCidrBlock": "10.70.0.0/16",
                    "State": "active",
                    "Type": "propagated",
                    "TransitGatewayAttachments": [
                        {"TransitGatewayAttachmentId": "tgw-attach-fake00001"}
                    ],
                }
            ]
        }

    def describe_subnets(self, **kwargs):
        self.calls.append(("subnets", kwargs["Filters"][0]["Values"]))
        return {
            "Subnets": [
                {
                    "SubnetId": "subnet-fake0a00001",
                    "VpcId": "vpc-fake000000001",
                    "AvailabilityZone": "eu-central-1a",
                    "CidrBlock": "10.70.0.0/20",
                }
            ]
        }

    def describe_vpcs(self, **kwargs):
        self.calls.append(("vpcs", kwargs["VpcIds"]))
        return {
            "Vpcs": [
                {
                    "VpcId": "vpc-fake000000001",
                    "CidrBlock": "10.70.0.0/16",
                    "CidrBlockAssociationSet": [{"CidrBlock": "10.70.0.0/16"}],
                }
            ]
        }


def test_collect_region_builds_a_replayable_payload():
    fake = FakeEc2()
    region = collect_region("eu-central-1", client=fake)

    assert region["transit_gateways"][0]["TransitGatewayId"] == "tgw-0fake000000001"
    assert region["associations"]["tgw-rtb-fake000001"][0]["State"] == "associated"
    assert region["routes"]["tgw-rtb-fake000001"][0]["DestinationCidrBlock"] == "10.70.0.0/16"
    assert ("vpcs", ["vpc-fake000000001"]) in fake.calls
    assert ("routes", ["active", "blackhole", "pending"]) in fake.calls

    topo = topologies_from_payload({"version": 1, "regions": {"eu-central-1": region}})[0]
    assert topo.association_table("tgw-attach-fake00001") == "tgw-rtb-fake000001"
    assert topo.attachment_cidrs("tgw-attach-fake00001") == ["10.70.0.0/16"]


def test_collect_region_skips_vpc_lookups_without_vpc_attachments():
    class NoVpcs(FakeEc2):
        def describe_transit_gateway_vpc_attachments(self, **kwargs):
            return {"TransitGatewayVpcAttachments": []}

    fake = NoVpcs()
    region = collect_region("eu-central-1", client=fake)
    assert region["subnets"] == []
    assert region["vpcs"] == []
    assert not any(isinstance(call, tuple) and call[0] == "vpcs" for call in fake.calls)
