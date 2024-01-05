import geoip2.database

from config import Config

from .Scan import Scan


class GeoIPScanner(Scan):
    @staticmethod
    def scan(target: str) -> dict:
        result = {}

        try:
            with geoip2.database.Reader(Config.geoip_city_path) as reader:
                response = reader.city(target)
        except Exception as e:
            return result

        result["country"] = response.country.name if response.country.name else ""
        result["city"] = response.city.name if response.city.name else ""

        return result
