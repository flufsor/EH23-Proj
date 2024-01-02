import geoip2.database

from config import Config

from .Scan import Scan


class ASNScanner(Scan):
    @staticmethod
    def scan(target: str) -> dict:
        result = {}

        try:
            with geoip2.database.Reader(Config.geoip_asn_path) as reader:
                response = reader.asn(target)

                result["ASN"] = (
                    f"AS{response.autonomous_system_number}"
                    if response.autonomous_system_number
                    else ""
                )

                result["Organization"] = (
                    response.autonomous_system_organization
                    if response.autonomous_system_organization
                    else ""
                )

                result["network"] = str(response.network) if response.network else ""

        except Exception as e:
            print(f"An error occurred during ASN scanning: {e}")
            pass

        return result

    @staticmethod
    def get_name() -> str:
        return "ASN Scanner"
