#! /usr/bin/env python3
import argparse
import json
from datetime import datetime
from os import remove

import dns
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
    parser.add_argument("-d", "--domainname_list", dest="config.domainname_list", help="List of domain names to use for subdomain brute forcing")
    parser.add_argument("-p", "--portrange", dest="config.portrange", help="Port range to scan")
    parser.add_argument("-i", "--lookup_expired", dest="config.crt_sh_ignore_expired", action="store_false", help="Do not ignore expired certificates from crt.sh")
    return parser.parse_args()

def print_header(console: Console):
    logo = r"""
                _________                                       
    ______ ___.__.\_   ___ \  _______  __ ___________ ___.__.   
    \____ <   |  |/    \  \/ /  _ \  \/ // __ \_  __ <   |  |   
    |  |_> >___  |\     \___(  <_> )   /\  ___/|  | \/\___  |   
    |   __// ____| \______  /\____/ \_/  \___  >__|   / ____|   
    |__|   \/             \/                 \/       \/        
    """
    print(Panel.fit(logo, width=console.width, style="bold green"))

    print("Configuration:")
    print(Padding(f"Target: [cyan]{args.domain}[/cyan]", (0, 4)))
    print(Padding(f"Output: [cyan]{args.output}[/cyan]", (0, 4)))
    print(Padding(f"Domain name list: [cyan]{config.domainname_list}[/cyan]", (0, 4)))
    print(Padding(f"Port range: [cyan]{config.portrange}[/cyan]", (0, 4)))
    print(Padding(f"Ignore expired certificates: [cyan]{config.crt_sh_ignore_expired}[/cyan]", (0, 4)))
    print()

def print_domain_info(domain_records: dict, dns_sec: bool):
    print(f"Domain info:")
    print(Padding(f"Found [cyan]{len(targets)}[/cyan] IP addresses for [cyan]{args.domain}[/cyan]", (0, 4)))

    # Run DNSSEC scanner
    if dns_sec:
        print(Padding(f"DNSSEC: [green]{dns_sec}[/green]", (0, 4)))
    else:
        print(Padding(f"DNSSEC: [red]{dns_sec}[/red]", (0, 4)))

    # Print domain records
    print(Padding("Subdomains:", (0, 4)))
    for subdomain, _ in domain_records.items():
        print(Padding(f"- [cyan]{subdomain}[/cyan]", (0, 8)))
    print()

def ip_info(targets: dict) -> dict:
    results = {}

    for index, target in enumerate(targets):
        print(f"Scanning IP {index+1}/{len(targets)}: {target}")

        # ASN scanner
        if Config.geoip_asn_path:
            targets[target]['network_info'] = ASScanner.scan(target)
            if not targets[target]['network_info']:
                print(Padding("Network Info: [red]Not found[/red]", (0, 4)))
            else:
                print(Padding("Network Info:", (0, 4)))
                print(Padding(f"AS: [cyan]{targets[target]['network_info']['AS']}[/cyan]", (0, 8)))
                print(Padding(f"Organization: [cyan]{targets[target]['network_info']['organization']}[/cyan]", (0, 8)))
                print(Padding(f"Network: [cyan]{targets[target]['network_info']['network']}[/cyan]", (0, 8)))
        else:
            print(Padding("Network Info: [yellow]Skipped[/yellow]", (0, 4)))

        # GeoIP scanner
        if Config.geoip_city_path != "":
            targets[target]["geoip"] = GeoIPScanner.scan(target)
            if not targets[target]["geoip"]:
                print(Padding("GeoIP: [red]Not found[/red]", (0, 4)))
            else:
                print(Padding(f"GeoIP:", (0, 4)))
                print(Padding(f"Country: [cyan]{targets[target]['geoip']['country']}[/cyan]", (0, 8)))
                print(Padding(f"City: [cyan]{targets[target]['geoip']['city']}[/cyan]", (0, 8)))
        else:
            print(Padding("GeoIP: [yellow]Skipped[/yellow]", (0, 4)))

        # Port scanner
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
                            if len(targets[target]["ports"][ssh_key]["weak_ciphers"][cipher_type]) > 0:
                                print(Padding(f"- {cipher_type}", (0, 12)))
                                for cipher in targets[target]["ports"][ssh_key]["weak_ciphers"][cipher_type]:
                                    print(Padding(f"- [bold red]{cipher}[/bold red]", (0, 16)))

        print()

    return results

def get_ips_from_domain_records(domain_records: dict[str, dict[str, str]]) -> list:
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

def remove_empty_arrays(data):
    for key, value in list(data.items()):
        if isinstance(value, dict):
            data[key] = remove_empty_arrays(value)
        elif isinstance(value, list) and not value:
            del data[key]

    return data


if __name__ == "__main__":
    console = Console()
    config = Config()
    args = parse_args()

    results = {
        "target": args.domain,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    targets = {}

    print_header(console)

    # Run DomainScans first
    domain_records = DomainScanner.scan(args.domain)
    crt_sh_results = CrtShScanner.scan(args.domain)

    for subdomain, records in crt_sh_results.items():
        domain_records.setdefault(subdomain, {}).update(records)
        for record_type, ips in records.items():
            domain_records[subdomain][record_type] = list(set(ips))

    targets = {value: {} for value in get_ips_from_domain_records(domain_records)}
    domain_records = remove_empty_arrays(domain_records)
    targets = remove_empty_arrays(targets)

    dns_sec = DnsSecScanner.scan(args.domain)

    
    print_domain_info(domain_records, dns_sec)

    # Run scans on ip addresses
    results["ips"] = ip_info(targets)

    # Write results to JSON file
    with open(args.output, "w") as json_file:
        json.dump({
            "target": args.domain,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "domain_info": {
                "dnssec": dns_sec,
                "subdomains": domain_records,
            },
            "ips": targets
        }, json_file,indent=2)

    print(f'\nScan results written to "[green]{args.output}[/green]"')
