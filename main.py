#! /usr/bin/env python3
import argparse
import json

from scans.DomainScanner import DomainScanner


def parse_args():
    parser = argparse.ArgumentParser(description="Cybersecurity scanning CLI tool")
    parser.add_argument("target", help="Target domain to scan")
    parser.add_argument("output", help="Output JSON file path")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    domain_scanner = DomainScanner(args.target)

    domain_scan_results = domain_scanner.scan()

    with open(args.output, "w") as json_file:
        json.dump(domain_scan_results, json_file, indent=2)
    print(f"Scan results written to {args.output}")
