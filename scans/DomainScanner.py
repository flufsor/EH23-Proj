import functools
import sys

import dns.rdatatype
import dns.resolver
import requests

from config import Config

from .Scan import Scan


class DomainScanner(Scan):
    @staticmethod
    def scan(target: str) -> dict:
        results = {
            target: {
                record_type: DomainScanner.get_dns_records(target, record_type)
                for record_type in ["A", "AAAA", "MX", "TXT"]
            }
        }

        for subdomain in DomainScanner.subdomain_name_list():
            full_domain = f"{subdomain}.{target}"
            try:
                dns.resolver.resolve(full_domain, "A")

                results[full_domain] = {
                    record_type: DomainScanner.get_dns_records(full_domain, record_type)
                    for record_type in ["A", "AAAA", "MX", "TXT"]
                }
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue

        return results

    @staticmethod
    def get_dns_records(target: str, record_type: str) -> list:
        try:
            result = dns.resolver.resolve(target, record_type)
            records = set()

            for answer in result.response.answer:
                for item in answer.items:
                    if item.rdtype == dns.rdatatype.A or item.rdtype == dns.rdatatype.AAAA:
                        records.add(str(item))
                    elif item.rdtype == dns.rdatatype.CNAME:
                        cname_target = str(item.target)
                        cname_records = DomainScanner.get_dns_records(cname_target, record_type)
                        records.update(cname_records)

            if record_type == "TXT":
                records = [record.strip('"') for record in records]

            return list(records)

        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NXDOMAIN:
            print(f"Error: {target} does not exist")
            sys.exit(1)

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

        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)

        return domain_list
