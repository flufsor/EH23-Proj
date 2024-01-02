#! /usr/bin/env python3
import argparse
import json
from datetime import datetime
from typing import Dict

from config import Config
from scans import DomainScanner, PortScanner


def parse_args():
    parser = argparse.ArgumentParser(description="Cybersecurity scanning CLI tool")
    parser.add_argument("domain", help="Domain to scan")
    parser.add_argument("output", help="Output JSON file path")
    return parser.parse_args()


def get_ips_from_domain_records(domain_records: Dict[str, Dict[str, str]]) -> list:
    if domain_records is None:
        return []

    unique_ips = set()
    for records in domain_records.values():
        for record_type, ip_list in records.items():
            if record_type in {"A", "AAAA"}:
                unique_ips.update(ip_list)
    return list(unique_ips)


if __name__ == "__main__":
    config = Config()
    args = parse_args()

    scans = {}
    domain_records = {}
    targets = {}

    # Run DomainScanner first so that we can use the found subdomains and IPs it finds in the other scanners
    print("Running Domain Scanner...")
    domain_records = DomainScanner.scan(args.domain)

    targets = {value: {} for value in get_ips_from_domain_records(domain_records)}

    print(f"Found {len(targets)} IP addresses for {args.domain}")

    # Run other scanners
    target_counter = 1
    for target in targets:
        print(f"Scanning IP {target_counter}/{len(targets)}")
        targets[target]["ports"] = PortScanner.scan(target)

        target_counter += 1

    # Write results to JSON file
    with open(args.output, "w") as json_file:
        json.dump(
            {
                "target": args.domain,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "domain_info": {
                    "domain_records": domain_records,
                },
                "hosts": targets,
            },
            json_file,
            indent=2,
        )

    print(f"\nScan results written to {args.output}")
