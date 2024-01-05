import re
from tracemalloc import DomainFilter

import dns.resolver
import requests

from config import Config

from .DomainScanner import DomainScanner
from .Scan import Scan


class CrtShScanner(Scan):
    @staticmethod
    def scan(target) -> dict:
        crt_sh_url = f"https://crt.sh/?q=%.{target}&output=json"
        if Config.crt_sh_ignore_expired:
            crt_sh_url += "&exclude=expired"

        response = requests.get(crt_sh_url)

        if response.status_code != 200:
            return {}

        crt_sh_results = response.json()
        results = {}
        for crt_sh_result in crt_sh_results:
            common_name = crt_sh_result["common_name"]

            try:
                dns.resolver.resolve(common_name, "A")
                if common_name not in results:
                    results[common_name] = {
                        record_type: DomainScanner.get_dns_records(common_name, record_type)
                        for record_type in ["A", "AAAA", "MX", "TXT"]
                    }

            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue

        return results
