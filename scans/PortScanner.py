from typing import Dict

import nmap

from config import Config

from .Scan import Scan


class PortScanner(Scan):
    def __init__(self, target: str):
        self.target = target

    def scan(self) -> Dict[str, Dict[int, str]]:
        try:
            nm = nmap.PortScanner()
            scan_results = nm.scan(
                hosts=self.target, ports=str(Config.portrange), arguments="-sV"
            )

            results_dict = {}

            for host, result in scan_results["scan"].items():
                host_results = {}

                if "tcp" in result:
                    for port, port_info in result["tcp"].items():
                        state = port_info.get("state", "unknown")
                        if state == "open":
                            host_results[port] = {
                                "product": port_info.get("product", "unknown"),
                                "version": port_info.get("version", "unknown"),
                            }

                results_dict[host] = host_results

            return results_dict

        except nmap.PortScannerError as e:
            print(f"An error occurred during port scanning: {e}")
            return {}

    @staticmethod
    def get_name() -> str:
        return "Port Scanner"
