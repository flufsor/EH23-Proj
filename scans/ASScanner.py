import geoip2.database

from config import Config

from .Scan import Scan


class ASScanner(Scan):
    @staticmethod
    def scan(target: str) -> dict:
        result = {}

        try:
            with geoip2.database.Reader(Config.geoip_asn_path) as reader:
                response = reader.asn(target)

                result["AS"] = f"AS{response.autonomous_system_number}" if response.autonomous_system_number else ""

                result["organization"] = (
                    response.autonomous_system_organization if response.autonomous_system_organization else ""
                )

                result["network"] = str(response.network) if response.network else ""

        except Exception as e:
            pass

        return result
