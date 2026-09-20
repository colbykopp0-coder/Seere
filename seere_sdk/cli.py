import argparse
import json
import os
import sys

from .core import SeereScanner, ScanConfig
from .cloud import SeereClient


def render(report):
    print("SEERE")
    print("=" * 60)
    print(f"Root: {report.root}")
    print(f"Findings: {report.stats['total_findings']}")
    print(
        f"Critical: {report.stats['critical']}  "
        f"High: {report.stats['high']}  "
        f"Medium: {report.stats['medium']}  "
        f"Low: {report.stats['low']}"
    )
    print()

    for finding in report.findings:
        location = (
            f"{finding.path}:{finding.line}"
            if finding.line
            else finding.path
        )
        print(f"[{finding.severity}] {finding.kind} ({finding.provider})")
        print(f"  {location}")
        print(f"  {finding.preview}  fp:{finding.fingerprint}")
        for note in finding.notes:
            print(f"  - {note}")
        print()


def main():
    parser = argparse.ArgumentParser(
        prog="seere",
        description="Local-first secret and machine identity scanner.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan")
    scan.add_argument("path", nargs="?", default=".")
    scan.add_argument("--git-history", action="store_true")
    scan.add_argument("--json", action="store_true")
    scan.add_argument("--push", action="store_true")

    args = parser.parse_args()

    fp_key = os.environ.get(
        "SEERE_FINGERPRINT_KEY",
        "seere-local-dev-key-change-me",
    ).encode()

    scanner = SeereScanner(
        ScanConfig(
            fingerprint_key=fp_key,
            scan_git_history=args.git_history,
        )
    )
    report = scanner.scan(args.path)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        render(report)

    if args.push:
        endpoint = os.environ.get("SEERE_ENDPOINT")
        token = os.environ.get("SEERE_TOKEN")

        if not endpoint or not token:
            print(
                "SEERE_ENDPOINT and SEERE_TOKEN are required for --push.",
                file=sys.stderr,
            )
            raise SystemExit(2)

        result = SeereClient(endpoint, token).push_report(report)
        print(f"Sent metadata to Sentinel: HTTP {result['status']}")


if __name__ == "__main__":
    main()
