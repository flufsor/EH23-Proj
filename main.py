#! /usr/bin/env python3
import argparse
import json
from datetime import datetime
from tabnanny import check
from typing import Dict

from config import Config
from scans import *


def parse_args():
    parser = argparse.ArgumentParser(description="Cybersecurity scanning CLI tool")
    parser.add_argument("domain", help="Domain to scan")
    parser.add_argument("output", help="Output JSON file path")
    return parser.parse_args()


def get_ips_from_domain_records(domain_records: Dict[str, Dict[str, str]]) -> list:
    """Returns a list of unique IP addresses from the given domain records"""
    if domain_records is None:
        return []

    unique_ips = set()
    for records in domain_records.values():
        for record_type, ip_list in records.items():
            if record_type in {"A", "AAAA"}:
                unique_ips.update(ip_list)
    return list(unique_ips)


def check_ports_for_service(target: dict, services: list[str]) -> list[int] | None:
    """Returns a list of ports that have the given services running on them or None if no ports are found"""
    ports = []

    print(target["ports"])

    for port in target.get("ports", []):
        service = target["ports"][port]["product"].lower()
        if service and service in services:
            ports.append(port)

    return ports if ports else None


if __name__ == "__main__":
    config = Config()
    args = parse_args()

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
        if Config.enable_asn:
            targets[target]["asn"] = ASNScanner.scan(target)
        if Config.enable_geoip:
            targets[target]["geoip"] = GeoIPScanner.scan(target)

        portscan_results = PortScanner.scan(target)
        for scanresult_key, scanresult_value in portscan_results.items():
            targets[target][scanresult_key] = scanresult_value

        # Check for ssh servers and scan them
        ports = check_ports_for_service(targets[target], Config.ssh_server_identifiers)
        if ports is not None:
            ssh_servers = {}
            for port in ports:
                ssh_servers[port] = SshScanner.scan(target, port)

            print("SSH Servers: ", ssh_servers)

            if len(ssh_servers) > 0:
                for ssh_key, ssh_value in ssh_servers.items():
                    targets[target]["ports"][ssh_key]["weak_ciphers"] = ssh_value

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
                "ips": targets,
            },
            json_file,
            indent=2,
        )

    print(f"\nScan results written to {args.output}")
