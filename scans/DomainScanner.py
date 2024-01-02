import sys

import dns.resolver

from .Scan import Scan


class DomainScanner(Scan):
    domainname_list = "small.txt"

    @staticmethod
    def scan(target: str) -> dict:
        def get_dns_records(target: str, record_type: str) -> list:
            try:
                result = dns.resolver.resolve(target, record_type)
                records = [
                    str(item)
                    for answer in result.response.answer
                    for item in answer.items
                ]

                if record_type == "TXT":
                    records = [record.strip('"') for record in records]

                return records
            except dns.resolver.NoAnswer:
                return []
            except dns.resolver.NXDOMAIN:
                return ["Domain not found"]

        def brute_force_and_scan_subdomains(target) -> dict:
            try:
                with open(DomainScanner.domainname_list, "r") as domainname_list_file:
                    subdomains_to_bruteforce = domainname_list_file.read().splitlines()
            except FileNotFoundError:
                print(f"Error: File not found: {DomainScanner.domainname_list}")
                sys.exit(1)

            results = {
                target: {
                    record_type: get_dns_records(target, record_type)
                    for record_type in ["A", "AAAA", "MX", "TXT"]
                }
            }

            for subdomain in subdomains_to_bruteforce:
                full_domain = f"{subdomain}.{target}"
                try:
                    dns.resolver.resolve(full_domain, "A")

                    results[full_domain] = {
                        record_type: get_dns_records(full_domain, record_type)
                        for record_type in ["A", "AAAA", "MX", "TXT"]
                    }
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    pass

            return results

        def remove_empty_arrays(data):
            for key, value in list(data.items()):
                if isinstance(value, dict):
                    remove_empty_arrays(value)
                elif isinstance(value, list) and not value:
                    del data[key]

            return data

        scan_results = brute_force_and_scan_subdomains(target)
        return remove_empty_arrays(scan_results)

    @staticmethod
    def get_name() -> str:
        return "Domain Name Scanner"

    @staticmethod
    def set_domainname_list(file_path: str):
        DomainScanner.domainname_list = file_path
