import functools
import sys

import dns.resolver

from config import Config

from .Scan import Scan


class DomainScanner(Scan):
    @staticmethod
    def scan(target: str) -> dict:
        def get_dns_records(target: str, record_type: str) -> list:
            try:
                result = dns.resolver.resolve(target, record_type)
                records = [str(item) for answer in result.response.answer for item in answer.items]

                if record_type == "TXT":
                    records = [record.strip('"') for record in records]

                return records
            except dns.resolver.NoAnswer:
                return []
            except dns.resolver.NXDOMAIN:
                return ["Domain not found"]

        def brute_force_and_scan_subdomains(target) -> dict:
            results = {
                target: {
                    record_type: get_dns_records(target, record_type) for record_type in ["A", "AAAA", "MX", "TXT"]
                }
            }

            for subdomain in DomainScanner.subdomain_name_list():
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
    @functools.lru_cache(maxsize=None)  # Cache the results of this function
    def subdomain_name_list():
        domain_list = []
        try:
            with open(Config.domainname_list, "r") as f:
                domain_list = f.read().splitlines()
        except FileNotFoundError:
            print(f"Error: File not found: {Config.domainname_list}")
            sys.exit(1)

        return domain_list
