# aws-transit-gateway-audit

[![ci](https://github.com/moveeeax/aws-transit-gateway-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/aws-transit-gateway-audit/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)](pyproject.toml)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A Transit Gateway is the one piece of AWS networking where nothing tells you it is broken. The
attachment says `available`, the route table exists, the console draws a neat hub and spoke, and
traffic still goes nowhere because the attachment was never associated with a route table, or it
propagates into a table that nothing consults.

This reads the topology with a handful of `describe`/`get`/`search` calls and tells you which spokes
are actually wired up.

## What it checks

| rule | severity | what it means |
| --- | --- | --- |
| `tgw-attachment-unassociated` | critical | `available` attachment associated with no route table: it sends nothing and is still billed |
| `tgw-attachment-no-propagation` | warn | attachment propagates into no table, so no spoke learns its prefixes |
| `tgw-attachment-one-way` | warn | association table learns nothing from the other spokes while they propagate elsewhere |
| `tgw-attachment-failed` | critical | attachment in `failed`, `failing`, `rejected` or `rejecting` |
| `tgw-attachment-pending` | warn | attachment stuck in `pendingAcceptance` past `--max-pending-age-days` |
| `tgw-attachment-az-gap` | warn | VPC attachment missing a subnet in an availability zone the VPC uses |
| `tgw-attachment-cidr-overlap` | warn | two attachments advertise overlapping CIDRs; longest prefix wins and the loser is unreachable |
| `tgw-attachment-idle` | warn | attachment wired up, propagating nowhere, target of no route: pure hourly cost |
| `tgw-route-blackhole` | warn | route discards traffic for its prefix |
| `tgw-route-dangling-target` | critical | route points at an attachment that is deleting or gone |
| `tgw-route-table-dead` | warn | route table with no associations and no propagations |

## How it works

Transit Gateway routing is three independent relations, shown on three different console screens: an
attachment is **associated** with exactly one route table, an attachment **propagates** its routes
into zero or more route tables, and a route table holds **routes**. Connectivity needs the
association and the propagation to line up in both directions, and nothing in AWS validates that.

So the tool splits cleanly in two:

- `collect.py` is the only module that talks to AWS. It calls `describe_transit_gateways`,
  `describe_transit_gateway_attachments`, `describe_transit_gateway_route_tables`,
  `describe_transit_gateway_vpc_attachments`, then per route table
  `get_transit_gateway_route_table_associations`,
  `get_transit_gateway_route_table_propagations` and `search_transit_gateway_routes`, plus
  `describe_subnets`/`describe_vpcs` for the attachment-level checks. Read-only, `ec2` only.
- `rules.py` is pure functions over a local model. Every rule is tested against JSON fixtures, with
  no credentials and no `moto`.

That split is why `--dump-json` and `--from-json` exist: record a payload once, then re-run the whole
audit offline as many times as you like.

## Install

```shell
pip install git+https://github.com/moveeeax/aws-transit-gateway-audit
```

IAM needs read-only EC2: `ec2:DescribeTransitGateway*`, `ec2:GetTransitGatewayRouteTable*`,
`ec2:SearchTransitGatewayRoutes`, `ec2:DescribeSubnets`, `ec2:DescribeVpcs`.

## Usage

```shell
aws-transit-gateway-audit --region eu-central-1
aws-transit-gateway-audit --regions eu-central-1,eu-west-1 --fail-on critical
aws-transit-gateway-audit --format json | jq '.attachments[] | select(.severity=="critical")'
aws-transit-gateway-audit --region eu-central-1 --dump-json tgw.json
aws-transit-gateway-audit --from-json examples/hub-and-spoke.json --format markdown
```

Against the broken example topology in `examples/`:

```shell
$ aws-transit-gateway-audit --from-json examples/hub-and-spoke.json
region eu-central-1
  CRIT  transit gateway tgw-0hub0000000000001 (core hub)
  WARN  attachment tgw-attach-prod000001
          [tgw-attachment-az-gap] tgw-attach-prod000001 (vpc vpc-prod000000000001) has no subnet in eu-central-1c, so traffic from that zone in vpc-prod000000000001 is dropped with no error
  CRIT  attachment tgw-attach-stage00001
          [tgw-attachment-unassociated] tgw-attach-stage00001 (vpc vpc-stage00000000001) is available but associated with no route table, so it sends nothing and is still billed
          [tgw-attachment-cidr-overlap] tgw-attach-stage00001 and tgw-attach-lab000001 both advertise 10.20.16.0/20; the longest prefix wins and the loser is unreachable through the gateway
  WARN  attachment tgw-attach-dmz000001
          [tgw-attachment-one-way] tgw-attach-dmz000001 (vpc vpc-dmz0000000000001) is associated with tgw-rtb-isolated000001, which no other spoke propagates into, while 3 attachment(s) propagate into tgw-rtb-shared00000001: reachability is one-way
  WARN  attachment tgw-attach-legacy0001
          [tgw-attachment-idle] tgw-attach-legacy0001 (vpn vpn-0legacy000000001) propagates nowhere and is the target of no route: it costs about 36.50 USD/month to route nothing
  CRIT  route table tgw-rtb-shared00000001
          [tgw-route-dangling-target] tgw-rtb-shared00000001 routes 172.16.9.0/24 to tgw-attach-gone00001, which is missing: the prefix resolves to nothing

11 finding(s): 3 critical, 8 warn across 7 attachment(s) and 3 route table(s)
$ echo $?
1
```

(trimmed; the real run also prints the blackhole, the pending peering, the failed attachment and the
dead route table)

### Flags

| flag | default | effect |
| --- | --- | --- |
| `--region` / `--regions` | — | one region, or a comma-separated list |
| `--profile` | default chain | AWS profile for collection |
| `--format` | `text` | `text`, `json` or `markdown` |
| `--fail-on` | `critical` | lowest severity that makes the exit code `1`; `warn` or `none` also accepted |
| `--rules` | — | YAML overriding thresholds, ignores and severities (see `examples/rules.yaml`) |
| `--attachment-monthly-cost` | `36.50` | monthly attachment price used by the waste rule |
| `--max-pending-age-days` | `7` | age at which `pendingAcceptance` becomes a finding |
| `--from-json` | — | replay a saved payload, no AWS calls |
| `--dump-json` | — | write the collected payload to a file |

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` bad input (a malformed payload or
rules file exits `2` with a message, never a traceback).

## In CI

```yaml
- name: Audit the transit gateway
  run: aws-transit-gateway-audit --regions eu-central-1,eu-west-1 --fail-on critical
```

## Development

```shell
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
ruff check . && pytest
```

MIT licensed.
