"""Turn findings into a report object, then render it as text, JSON or Markdown."""

from __future__ import annotations

import json

from .model import Finding, Topology, worst

REPORT_VERSION = 1
MARK = {"ok": "ok", "warn": "WARN", "critical": "CRIT"}


def _findings_for(findings: list[Finding], scope: str, target: str) -> list[Finding]:
    return [f for f in findings if f.scope == scope and f.target == target]


def _severity(findings: list[Finding]) -> str:
    return worst(*(f.severity for f in findings)) if findings else "ok"


def build_report(results: list[tuple[Topology, list[Finding]]]) -> dict:
    """Assemble the document every renderer reads."""
    gateways: list[dict] = []
    attachments: list[dict] = []
    route_tables: list[dict] = []
    all_findings: list[Finding] = []

    for topo, findings in results:
        all_findings.extend(findings)

        for attachment in topo.attachments:
            att_id = attachment.get("TransitGatewayAttachmentId")
            if not att_id:
                continue
            own = _findings_for(findings, "attachment", att_id)
            attachments.append(
                {
                    "id": att_id,
                    "region": topo.region,
                    "transit_gateway_id": attachment.get("TransitGatewayId", ""),
                    "resource_type": attachment.get("ResourceType"),
                    "resource_id": attachment.get("ResourceId"),
                    "state": attachment.get("State"),
                    "association_route_table": topo.association_table(att_id),
                    "propagation_route_tables": topo.propagation_tables(att_id),
                    "severity": _severity(own),
                    "findings": [f.to_dict() for f in own],
                }
            )

        for table in topo.route_tables:
            table_id = table.get("TransitGatewayRouteTableId")
            if not table_id:
                continue
            own = _findings_for(findings, "route_table", table_id)
            route_tables.append(
                {
                    "id": table_id,
                    "region": topo.region,
                    "transit_gateway_id": table.get("TransitGatewayId", ""),
                    "associations": len(topo.associations.get(table_id, [])),
                    "propagations": len(topo.propagations.get(table_id, [])),
                    "routes": len(topo.routes.get(table_id, [])),
                    "default_association": bool(table.get("DefaultAssociationRouteTable")),
                    "severity": _severity(own),
                    "findings": [f.to_dict() for f in own],
                }
            )

        for gateway in topo.gateways:
            gw_id = gateway.get("TransitGatewayId")
            if not gw_id:
                continue
            own = _findings_for(findings, "gateway", gw_id)
            child = [f for f in findings if f.gateway == gw_id and f.scope != "gateway"]
            gateways.append(
                {
                    "id": gw_id,
                    "region": topo.region,
                    "state": gateway.get("State"),
                    "description": gateway.get("Description"),
                    "attachments": len(topo.gateway_attachments(gw_id)),
                    "route_tables": len(topo.gateway_tables(gw_id)),
                    "severity": _severity(own + child),
                    "findings": [f.to_dict() for f in own],
                }
            )

    counts = {"critical": 0, "warn": 0}
    for finding in all_findings:
        if finding.severity in counts:
            counts[finding.severity] += 1

    return {
        "version": REPORT_VERSION,
        "regions": [topo.region for topo, _ in results],
        "summary": {
            "gateways": len(gateways),
            "attachments": len(attachments),
            "route_tables": len(route_tables),
            "findings": len(all_findings),
            "critical": counts["critical"],
            "warn": counts["warn"],
            "severity": worst(*(f.severity for f in all_findings)) if all_findings else "ok",
        },
        "gateways": gateways,
        "attachments": attachments,
        "route_tables": route_tables,
        "findings": [f.to_dict() for f in all_findings],
    }


def render_json(report: dict) -> str:
    return json.dumps(report, indent=2, sort_keys=False, default=str)


def _entity_lines(entities: list[dict], label: str, lines: list[str]) -> None:
    for entity in entities:
        if entity["severity"] == "ok" and not entity["findings"]:
            continue
        lines.append(f"  {MARK[entity['severity']]:>4}  {label} {entity['id']}")
        for finding in entity["findings"]:
            lines.append(f"          [{finding['rule']}] {finding['message']}")


def render_text(report: dict) -> str:
    lines: list[str] = []
    for region in report["regions"]:
        lines.append(f"region {region}")
        gateways = [g for g in report["gateways"] if g["region"] == region]
        if not gateways:
            lines.append("  no transit gateways found")
        for gateway in gateways:
            head = f"  {MARK[gateway['severity']]:>4}  transit gateway {gateway['id']}"
            if gateway.get("description"):
                head += f" ({gateway['description']})"
            lines.append(head)
            for finding in gateway["findings"]:
                lines.append(f"          [{finding['rule']}] {finding['message']}")
            _entity_lines(
                [a for a in report["attachments"] if a["transit_gateway_id"] == gateway["id"]],
                "attachment",
                lines,
            )
            _entity_lines(
                [t for t in report["route_tables"] if t["transit_gateway_id"] == gateway["id"]],
                "route table",
                lines,
            )
        lines.append("")

    orphans = [
        e
        for kind in ("attachments", "route_tables")
        for e in report[kind]
        if not e["transit_gateway_id"] and e["findings"]
    ]
    if orphans:
        lines.append("unattached objects")
        _entity_lines(orphans, "object", lines)
        lines.append("")

    summary = report["summary"]
    lines.append(
        f"{summary['findings']} finding(s): {summary['critical']} critical, {summary['warn']} warn "
        f"across {summary['attachments']} attachment(s) and "
        f"{summary['route_tables']} route table(s)"
    )
    return "\n".join(lines)


def render_markdown(report: dict) -> str:
    summary = report["summary"]
    lines = [
        "# Transit Gateway audit",
        "",
        f"Regions: {', '.join(report['regions']) or 'none'}",
        "",
        "| severity | count |",
        "| --- | --- |",
        f"| critical | {summary['critical']} |",
        f"| warn | {summary['warn']} |",
        "",
    ]
    if not report["findings"]:
        lines.append("No findings.")
        return "\n".join(lines)

    lines += ["| severity | rule | region | object | detail |", "| --- | --- | --- | --- | --- |"]
    order = {"critical": 0, "warn": 1, "ok": 2}

    def rank(finding: dict) -> tuple:
        return (order.get(finding["severity"], 3), finding["rule"], finding["target"])

    for finding in sorted(report["findings"], key=rank):
        detail = finding["message"].replace("|", "\\|")
        lines.append(
            f"| {finding['severity']} | `{finding['rule']}` | {finding['region']} | "
            f"`{finding['target']}` | {detail} |"
        )
    return "\n".join(lines)


RENDERERS = {"text": render_text, "json": render_json, "markdown": render_markdown}


def render(report: dict, fmt: str) -> str:
    return RENDERERS[fmt](report)
