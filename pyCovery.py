#! /usr/bin/env python3
import argparse
import json
import socket
from datetime import datetime

from rich import print
from rich.console import Console
from rich.padding import Padding
from rich.panel import Panel
from rich.progress import (BarColumn, Progress, SpinnerColumn,
                           TaskProgressColumn, TextColumn)

from config import Config
from scans import *


def parse_args():
    parser = argparse.ArgumentParser(description="Cybersecurity scanning CLI tool")
    parser.add_argument("domain", help="Domain to scan")
    parser.add_argument("output", help="Output JSON file path")
    parser.add_argument(
        "-d",
        "--domainname_list",
        dest="domainname_list",
        help="List of domain names to use for subdomain brute forcing",
    )
    parser.add_argument("-p", "--portrange", dest="portrange", help="Port range to scan")
    parser.add_argument(
        "-l",
        "--lookup_expired",
        dest="crt_sh_ignore_expired",
        action="store_false",
        help="Do not ignore expired certificates from crt.sh",
    )

    args = parser.parse_args()

    if args.domainname_list:
        Config.domainname_list = args.domainname_list
    if args.portrange:
        Config.portrange = args.portrange
    if args.crt_sh_ignore_expired is not None:
        Config.crt_sh_ignore_expired = args.crt_sh_ignore_expired

    return args


def print_header(console: Console):
    logo = r"""
                  _________                                       
    ______ ___.__.\_   ___ \  _______  __ ___________ ___.__.   
    \____ <   |  |/    \  \/ /  _ \  \/ // __ \_  __ <   |  |   
    |  |_> >___  |\     \___(  <_> )   /\  ___/|  | \/\___  |   
    |   __// ____| \______  /\____/ \_/  \___  >__|   / ____|   
    |__|   \/             \/                 \/       \/        
    """
    console.print(Panel.fit(logo, style="bold green"), justify="center")

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


def get_reverse_dns(ip: str):
    try:
        targets[ip]["rdns"] = socket.gethostbyaddr(ip)[0]
        print(Padding(f"RDNS: [cyan]{targets[ip]["rdns"]}[/cyan]", (0, 4)))
    except:
        targets[ip]["rdns"] = "unknown"
        print(Padding(f"RDNS: [red]{targets[ip]["rdns"]}[/red]", (0, 4)))
    

def print_geoip(geoip_data: dict):
    if not geoip_data:
        print(Padding("GeoIP: [red]Not found[/red]", (0, 4)))
    else:
        print(Padding(f"GeoIP:", (0, 4)))
        print(Padding(f"Country: [cyan]{geoip_data['country']}[/cyan]", (0, 8)))
        print(Padding(f"City: [cyan]{geoip_data['city']}[/cyan]", (0, 8)))


def print_asn(asn_data: dict):
    if not asn_data:
        print(Padding("Network Info: [red]Not found[/red]", (0, 4)))
    else:
        print(Padding("Network Info:", (0, 4)))
        print(Padding(f"AS: [cyan]{asn_data['AS']}[/cyan]", (0, 8)))
        print(Padding(f"Organization: [cyan]{asn_data['organization']}[/cyan]", (0, 8)))
        print(Padding(f"Network: [cyan]{asn_data['network']}[/cyan]", (0, 8)))


def print_portscan_results(portscan_results: dict):
    if "ports" not in portscan_results:
        print(Padding("Open Ports: [green]None[/green]", (0, 4)))
        return

    print(Padding(f"Open Ports:", (0, 4)))
    for port, port_info in portscan_results["ports"].items():
        print(
            Padding(
                f"- [bold yellow]{port}, Product: {port_info["product"]} Version:{port_info["version"]}[/bold yellow]",
                (0, 8),
            )
        )


def print_sshscan_weakciphers(ssh_servers: dict):
    print(Padding(f"SSH Servers:", (0, 4)))
    for port, ssh_server_info in ssh_servers.items():
        print(Padding(f"- Port: [bold yellow]{port}[/bold yellow]", (0, 8)))

        weak_ciphers = ssh_server_info.get("weak_ciphers", {})
        for cipher_type, ciphers in weak_ciphers.items():
            if ciphers:
                print(Padding(f"- [bold red]Found weak ciphers for {cipher_type}:[/bold red]", (0, 12)))
                for cipher in ciphers:
                    print(Padding(f"- [bold red]{cipher}[/bold red]", (0, 16)))


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


if __name__ == "__main__":
    console = Console()
    config = Config()
    args = parse_args()

    start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print_header(console)

    # Run DomainScans first
    domain_records = DomainScanner.scan(config, args.domain)
    crt_sh_results = CrtShScanner.scan(config, args.domain)

    for subdomain, records in crt_sh_results.items():
        domain_records.setdefault(subdomain, {}).update(records)
        for record_type, ips in records.items():
            domain_records[subdomain][record_type] = list(set(ips))

    targets = {value: {} for value in get_ips_from_domain_records(domain_records)}
    domain_records = Utility.remove_empty_arrays(domain_records)

    dns_sec = DnsSecScanner.scan(config, args.domain)

    print_domain_info(domain_records, dns_sec)

    # Run scans on ip addresses
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),BarColumn(), TaskProgressColumn()) as progress:
        task = progress.add_task("[cyan]Scanning IPs...", total=len(targets))

        for index, ip in enumerate(targets):
            ip_scanning_task = f"Scanning IP {index + 1}/{len(targets)}: {ip}"
            progress.update(task, description=ip_scanning_task, advance=1)

            print(f"IP: [cyan]{ip}[/cyan]")
            get_reverse_dns(ip) # Get reverse DNS

            # Run GeoIP scan
            if Config.geoip_city_path != "":
                targets[ip]["geoip"] = GeoIPScanner.scan(config, ip)
                print_geoip(targets[ip]["geoip"])
            else:
                print(Padding("GeoIP: [yellow]Skipped[/yellow]", (0, 4)))

            # Run ASN scan
            if Config.geoip_asn_path != "":
                targets[ip]["network_info"] = ASScanner.scan(config, ip)
                print_asn(targets[ip]["network_info"])
            else:
                print(Padding("Network Info: [yellow]Skipped[/yellow]", (0, 4)))

            # Run port scan
            portscan_results = PortScanner.scan(config, ip)
            for scanresult_key, scanresult_value in portscan_results.items():
                targets[ip][scanresult_key] = scanresult_value

            print_portscan_results(portscan_results)

            # Check for SSH servers and scan them
            ssh_ports = Utility.check_ports_for_service(targets[ip], Config.ssh_server_identifiers)
            if ssh_ports:
                targets[ip]["ssh"] = {}
                for port in ssh_ports:
                    targets[ip]["ssh"][port] = {"weak_ciphers": SshScanner.scan(config, ip, port)}
                
                Utility.remove_empty_arrays(targets[ip]["ssh"])
                print_sshscan_weakciphers(targets[ip]["ssh"])

            print()
        progress.stop()

    # Write results to JSON file
    try:
        with open(args.output, "w") as json_file:
            json.dump(
                {
                    "target": args.domain,
                    "start_time": start_time,
                    "end_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "domain_info": {
                        "dnssec": dns_sec,
                        "subdomains": domain_records,
                    },
                    "ips": targets,
                },
                json_file,
                indent=2,
            )

        print(f'\nScan results written to "[green]{args.output}[/green]"')
    except:
        print(f"Error writing scan results to file \"{args.output}\"")
