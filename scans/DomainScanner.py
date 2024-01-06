import sys

import dns.rdatatype
import dns.resolver

from config import Config

from .Scan import Scan


class DomainScanner(Scan):
    @staticmethod
    def scan(config: Config, target: str) -> dict:
        results = {
            target: {
                record_type: DomainScanner.get_dns_records(target, record_type)
                for record_type in ["A", "AAAA", "MX", "TXT"]
            }
        }

        with open(config.domainname_list, "r") as f:
            subdomain_name_list = f.read().splitlines()
            for subdomain in subdomain_name_list:
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

            for item in result:
                if item.rdtype == dns.rdatatype.A or item.rdtype == dns.rdatatype.AAAA:
                    records.add(str(item))
                elif item.rdtype == dns.rdatatype.CNAME:
                    cname_target = str(item.target)
                    cname_records = DomainScanner.get_dns_records(cname_target, record_type)
                    records.update(cname_records)
                elif item.rdtype == dns.rdatatype.MX:
                    mx_target = str(item.exchange)
                    mx_records = DomainScanner.get_dns_records(mx_target, record_type)
                    records.update(mx_records)
                elif item.rdtype == dns.rdatatype.TXT:
                    records.add(item.strings[0].decode('utf-8'))

            return list(records)

        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NXDOMAIN:
            print(f"Error: {target} does not exist")
            sys.exit(1)
