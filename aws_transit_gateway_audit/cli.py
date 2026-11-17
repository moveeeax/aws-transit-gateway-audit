"""Command line entry point.

Exit codes: 0 clean, 1 findings at or above `--fail-on`, 2 bad input.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .config import RulesError, load_rules
from .model import PayloadError, topologies_from_payload
from .report import RENDERERS, build_report, render
from .rules import RULE_HELP, Engine

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aws-transit-gateway-audit",
        description="Audit Transit Gateway wiring, routing and attachment health.",
        epilog="rules: " + "; ".join(f"{name} = {text}" for name, text in RULE_HELP.items()),
    )
    parser.add_argument("--region", help="single region to audit")
    parser.add_argument("--regions", help="comma-separated regions to audit")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument(
        "--format", choices=sorted(RENDERERS), default="text", help="output format"
    )
    parser.add_argument(
        "--fail-on",
        choices=("warn", "critical", "none"),
        default="critical",
        help="lowest severity that makes the exit code 1 (default: critical)",
    )
    parser.add_argument("--rules", help="YAML file overriding thresholds and cost constants")
    parser.add_argument(
        "--attachment-monthly-cost",
        type=float,
        help="monthly cost of one attachment, used by the waste rule",
    )
    parser.add_argument(
        "--max-pending-age-days",
        type=int,
        help="age at which a pendingAcceptance attachment becomes a finding",
    )
    parser.add_argument("--from-json", help="replay a payload recorded with --dump-json")
    parser.add_argument("--dump-json", help="write the collected payload to this file")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def resolve_regions(args: argparse.Namespace) -> list[str]:
    names: list[str] = []
    if args.region:
        names.append(args.region.strip())
    if args.regions:
        names.extend(part.strip() for part in args.regions.split(",") if part.strip())
    seen: dict[str, None] = {}
    for name in names:
        seen.setdefault(name, None)
    return list(seen)


def load_payload(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as exc:
        raise PayloadError(f"cannot read {path}: {exc.strerror}") from exc
    except json.JSONDecodeError as exc:
        raise PayloadError(f"{path} is not valid JSON: {exc}") from exc


def _exit_code(report: dict, fail_on: str) -> int:
    if fail_on == "none":
        return EXIT_OK
    severity = report["summary"]["severity"]
    if severity == "critical":
        return EXIT_FINDINGS
    if severity == "warn" and fail_on == "warn":
        return EXIT_FINDINGS
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        rules = load_rules(args.rules)
    except RulesError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    if args.attachment_monthly_cost is not None:
        if args.attachment_monthly_cost < 0:
            print("error: --attachment-monthly-cost must not be negative", file=sys.stderr)
            return EXIT_USAGE
        rules.attachment_monthly_cost = args.attachment_monthly_cost
    if args.max_pending_age_days is not None:
        if args.max_pending_age_days < 0:
            print("error: --max-pending-age-days must not be negative", file=sys.stderr)
            return EXIT_USAGE
        rules.max_pending_age_days = args.max_pending_age_days

    regions = resolve_regions(args)
    if args.from_json:
        try:
            payload = load_payload(args.from_json)
        except PayloadError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_USAGE
    else:
        if not regions:
            print("error: pass --region/--regions, or --from-json to replay", file=sys.stderr)
            return EXIT_USAGE
        from .collect import CollectError, collect

        try:
            payload = collect(regions, profile=args.profile)
        except CollectError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_USAGE

    if args.dump_json:
        try:
            with open(args.dump_json, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, default=str)
        except OSError as exc:
            print(f"error: cannot write {args.dump_json}: {exc.strerror}", file=sys.stderr)
            return EXIT_USAGE

    try:
        topologies = topologies_from_payload(payload)
    except PayloadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if args.from_json and regions:
        wanted = set(regions)
        topologies = [t for t in topologies if t.region in wanted]
        if not topologies:
            print(f"error: payload has no region matching {', '.join(regions)}", file=sys.stderr)
            return EXIT_USAGE

    engine = Engine(rules=rules)
    results = [(topo, engine.run(topo)) for topo in topologies]
    report = build_report(results)
    print(render(report, args.format))
    return _exit_code(report, args.fail_on)


def run() -> None:  # console-script shim
    sys.exit(main())


if __name__ == "__main__":  # pragma: no cover
    run()
