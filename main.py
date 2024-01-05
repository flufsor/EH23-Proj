#! /usr/bin/env python3
import argparse
import enum
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

    for port in target.get("ports", []):
        service = target["ports"][port]["product"].lower()
        if service and service in services:
            ports.append(port)

    return ports if ports else None


if __name__ == "__main__":
    console = Console()
    config = Config()
    args = parse_args()

    domain_records = {}
    targets = {}

    print_banner(console)

    print("Configuration:")
    print(Padding(f"Target: [cyan]{args.domain}[/cyan]", (0, 4)))
    print(Padding(f"Output: [cyan]{args.output}[/cyan]", (0, 4)))
    print()

    # Run DomainScans first so that we can use the found subdomains and IPs it finds in the other scanners
    domain_records = DomainScanner.scan(args.domain)

    targets = {value: {} for value in get_ips_from_domain_records(domain_records)}
    print(f"Domain info:")
    print(Padding(f"Found [cyan]{len(targets)}[/cyan] IP addresses for [cyan]{args.domain}[/cyan]", (0, 4)))

    # Run DNSSEC scanner
    dns_sec = DnsSecScanner.scan(args.domain)["dnssec"]
    if dns_sec:
        print(Padding(f"DNSSEC: [green]{dns_sec}[/green]", (0, 4)))
    else:
        print(Padding(f"DNSSEC: [red]{dns_sec}[/red]", (0, 4)))

    # Print domain records
    print(Padding("Subdomains:", (0, 4)))
    for subdomain, records in domain_records.items():
        print(Padding(f"- [cyan]{subdomain}[/cyan]", (0, 8)))
    print()

    # Run other scanners
    for index, target in enumerate(targets):
        print(f"Scanning IP {index+1}/{len(targets)}: {target}")

        if Config.geoip_asn_path != "":
            targets[target]["network_info"] = ASScanner.scan(target)
            print(Padding(f"Network Info:", (0, 4)))
            print(Padding(f"AS: [cyan]{targets[target]['network_info']["AS"]}[/cyan]", (0, 8)))
            print(Padding(f"Organization: [cyan]{targets[target]['network_info']["organization"]}[/cyan]", (0, 8)))
            print(Padding(f"Network: [cyan]{targets[target]['network_info']["network"]}[/cyan]", (0, 8)))
        else:
            print(Padding("ASN: [yellow]Skipped[/yellow]", (0, 4)))

        if Config.geoip_city_path != "":
            targets[target]["geoip"] = GeoIPScanner.scan(target)
            print(Padding(f"GeoIP:", (0, 4)))
            print(Padding(f"Country: [cyan]{targets[target]['geoip']['country']}[/cyan]", (0, 8)))
            print(Padding(f"City: [cyan]{targets[target]['geoip']['city']}[/cyan]", (0, 8)))

        else:
            print(Padding("GeoIP: [yellow]Skipped[/yellow]", (0, 4)))

        portscan_results = PortScanner.scan(target)
        for scanresult_key, scanresult_value in portscan_results.items():
            targets[target][scanresult_key] = scanresult_value
        
        if "ports" not in targets[target]:
            print(Padding("Open Ports: [green]None[/green]", (0, 4)))
            continue

        print(Padding(f"Open Ports:", (0, 4)))
        for port in targets[target]["ports"]:
            print(Padding(f"- [bold yellow]{port}, {targets[target]["ports"][port]['product']} {targets[target]["ports"][port]['version']}[/bold yellow]", (0, 8)))

        # Check for ssh servers and scan them
        ports = check_ports_for_service(targets[target], Config.ssh_server_identifiers)
        if ports is not None:
            ssh_servers = {}
            for port in ports:
                ssh_servers[port] = SshScanner.scan(target, port)

            if len(ssh_servers) > 0:
                print(Padding(f"SSH Servers:", (0, 4)))
                for ssh_key, ssh_value in ssh_servers.items():
                    targets[target]["ports"][ssh_key]["weak_ciphers"] = ssh_value
                    print(Padding(f"- Port: [bold yellow]{ssh_key}[/bold yellow]", (0, 8)))

                    # Check for weak ciphers
                    for cipher_type in targets[target]["ports"][ssh_key]["weak_ciphers"]:
                        if len(cipher_type) > 0:
                            weak_ciphers = True
                            break
                    else:
                        weak_ciphers = False
                    
                    if weak_ciphers:
                        print(Padding(f"- [bold red]Found weak ciphers:[/bold red]", (0, 8)))
                        for cipher_type in targets[target]["ports"][ssh_key]["weak_ciphers"]:
                            print(Padding(f"- {cipher_type}", (0, 12)))
                            for cipher in targets[target]["ports"][ssh_key]["weak_ciphers"][cipher_type]:
                                print(Padding(f"- [bold red]{cipher}[/bold red]", (0, 16)))

        print()

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

    print(f'\nScan results written to "[green]{args.output}[/green]"')
