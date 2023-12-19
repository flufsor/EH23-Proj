import sys

import dns.resolver

from config import Config

from .Scan import Scan


class DomainScanner(Scan):
    def __init__(self, target: str):
        self.target = target

    def scan(self) -> dict:
        subdomains_and_records = self._brute_force_and_scan_subdomains()
        scan_results = {
            "dns_records": subdomains_and_records,
        }

        self._remove_empty_arrays(scan_results["dns_records"])

        return scan_results

    @staticmethod
    def get_name() -> str:
        return "Domain Name Scanner"

    def _get_dns_records(self, target: str, record_type: str) -> list:
        try:
            result = dns.resolver.resolve(target, record_type)
            records = [
                str(item) for answer in result.response.answer for item in answer.items
            ]

            if record_type == "TXT":
                records = [record.strip('"') for record in records]

            return records
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NXDOMAIN:
            return ["Domain not found"]

    def _brute_force_and_scan_subdomains(self) -> dict:
        try:
            with open(Config.domainname_list, "r") as domainname_list_file:
                subdomains_to_bruteforce = domainname_list_file.read().splitlines()
        except FileNotFoundError:
            print(f"Error: File not found: {Config.domainname_list}")
            sys.exit(1)

        subdomains_and_records = {
            "@": {
                record_type: self._get_dns_records(self.target, record_type)
                for record_type in ["A", "AAAA", "MX", "TXT"]
            }
        }

        for subdomain in subdomains_to_bruteforce:
            full_domain = f"{subdomain}.{self.target}"
            try:
                dns.resolver.resolve(full_domain, "A")

                subdomains_and_records[full_domain] = {
                    record_type: self._get_dns_records(full_domain, record_type)
                    for record_type in ["A", "AAAA", "MX", "TXT"]
                }
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass

        return subdomains_and_records

    def _remove_empty_arrays(self, data):
        for key, value in list(data.items()):
            if isinstance(value, dict):
                self._remove_empty_arrays(value)
            elif isinstance(value, list) and not value:
                del data[key]

        return data
