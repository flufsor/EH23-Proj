#! /usr/bin/env python3
import argparse
import json
from ctypes.wintypes import tagRECT

from config import Config
from scans import DomainScanner, PortScanner


def parse_args():
    parser = argparse.ArgumentParser(description="Cybersecurity scanning CLI tool")
    parser.add_argument("target", help="Target domain to scan")
    parser.add_argument("output", help="Output JSON file path")
    return parser.parse_args()


if __name__ == "__main__":
    config = Config()
    args = parse_args()

    sub_targets = []

    scans = {}
    scan_results = {}

    for scanner in [DomainScanner, PortScanner]:
        scans[scanner.get_name()] = scanner(args.target)

    for scanner in scans.values():
        print(f"Running {scanner.get_name()}...")
        scan_results[scanner.get_name()] = scanner.scan()

    with open(args.output, "w") as json_file:
        json.dump({"target": args.target, "results": scan_results}, json_file, indent=2)

    print(f"Scan results written to {args.output}")
