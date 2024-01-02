import nmap

from config import Config

from .Scan import Scan


class PortScanner(Scan):
    @staticmethod
    def scan(target: str) -> dict:
        portscan_result = {}

        try:
            nm = nmap.PortScanner()
            scan_results = nm.scan(
                hosts=target, ports=str(Config.portrange), arguments="-sV"
            )

            for host, result in scan_results.get("scan", {}).items():
                for hostname in result.get("hostnames", []):
                    if hostname.get("type") == "PTR":
                        portscan_result["rdns"] = hostname.get("name", "")

                for port, port_info in result.get("tcp", {}).items():
                    state = port_info.get("state", "unknown")
                    if state == "open":
                        portscan_result[port] = {
                            "product": port_info.get("product", "unknown"),
                            "version": port_info.get("version", "unknown"),
                        }

        except nmap.PortScannerError as e:
            print(f"An error occurred during port scanning: {e}")

        return portscan_result

    @staticmethod
    def get_name() -> str:
        return "Port Scanner"
