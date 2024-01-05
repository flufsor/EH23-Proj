import geoip2.database

from config import Config

from .Scan import Scan


class ASScanner(Scan):
    @staticmethod
    def scan(config: Config, target: str) -> dict:
        result = {}

        try:
            with geoip2.database.Reader(config.geoip_asn_path) as reader:
                response = reader.asn(target)

        except Exception as e:
            return result

        result["AS"] = f"AS{response.autonomous_system_number}"
        result["organization"] = response.autonomous_system_organization
        result["network"] = str(response.network)

        return result
