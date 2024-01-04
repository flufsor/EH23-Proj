#! /usr/bin/env python3
import argparse
import json
from datetime import datetime
from typing import Dict

from rich import print
from rich.console import Console
from rich.padding import Padding
from rich.panel import Panel

from config import Config
from scans import *


def parse_args():
    parser = argparse.ArgumentParser(description="Cybersecurity scanning CLI tool")
    parser.add_argument("domain", help="Domain to scan")
    parser.add_argument("output", help="Output JSON file path")
    parser.add_argument("--banner", action="store_true", help="Print the welcome banner")
    return parser.parse_args()


def print_banner(console: Console):
    logo = r"""
                _________                                       
    ______ ___.__.\_   ___ \  _______  __ ___________ ___.__.   
    \____ <   |  |/    \  \/ /  _ \  \/ // __ \_  __ <   |  |   
    |  |_> >___  |\     \___(  <_> )   /\  ___/|  | \/\___  |   
    |   __// ____| \______  /\____/ \_/  \___  >__|   / ____|   
    |__|   \/             \/                 \/       \/        
    """
    horizontal_center = (console.width - max(len(line) for line in logo.splitlines())) // 2

    print(Panel.fit(logo, width=console.width, style="bold green"))
    print("Configuration:")
    print(Padding(f"Target: [bold cyan]{args.domain}[/bold cyan]", (0, 4)))
    print(Padding(f"Output: [bold cyan]{args.output}[/bold cyan]", (0, 4)))


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
    console = Console()
    config = Config()
    args = parse_args()

    if args.banner:
        print_banner(console)
        exit(0)

    domain_records = {}
    targets = {}

    # Run DomainScans first so that we can use the found subdomains and IPs it finds in the other scanners
    print("\n[yellow]Running Domain Scanner...[/yellow]")
    domain_records = DomainScanner.scan(args.domain)

    targets = {value: {} for value in get_ips_from_domain_records(domain_records)}

    print(f"Found [bold green]{len(targets)}[/bold green] IP addresses for {args.domain}")

    # Run DNSSEC scanner
    print("\n[yellow]Running DNSSEC Scanner...[/yellow]")
    dns_sec = DnsSecScanner.scan(args.domain)["dnssec"]

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
                    "dnssec": dns_sec,
                    "domain_records": domain_records,
                },
                "ips": targets,
            },
            json_file,
            indent=2,
        )

    pprint(f"\nScan results written to {args.output}")
