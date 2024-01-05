import nmap

from config import Config

from .Scan import Scan


class PortScanner(Scan):
    @staticmethod
    def scan(config: Config, target: str) -> dict:
        portscan_result = {}

        try:
            nm = nmap.PortScanner()
            scan_results = nm.scan(hosts=target, ports=str(config.portrange), arguments="-sV")

            for _, result in scan_results.get("scan", {}).items():
                portscan_result["ports"] = {}
                for port, port_info in result.get("tcp", {}).items():
                    state = port_info.get("state", "unknown")
                    if state == "open":
                        product = port_info.get("product", "").strip() or "unknown"
                        version = port_info.get("version", "").strip() or "unknown"
                        portscan_result["ports"][port] = {
                            "product": product,
                            "version": version,
                        }

        except Exception as e:
            return {}

        return portscan_result
