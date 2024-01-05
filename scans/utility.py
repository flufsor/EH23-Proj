import socket


class Utility:
    @staticmethod
    def check_ports_for_service(target: dict, services: list[str]) -> list[int]:
        """Returns a list of ports that have the given services running on them or None if no ports are found"""
        ports = []

        for port in target.get("ports", []):
            service = target["ports"][port]["product"].lower()
            if service and service in services:
                ports.append(port)

        return ports

    @staticmethod
    def remove_empty_arrays(data: dict) -> dict:
        for key, value in list(data.items()):
            if isinstance(value, dict):
                data[key] = Utility.remove_empty_arrays(value)
            elif isinstance(value, list) and not value:
                del data[key]

        return data

    @staticmethod
    def get_reverse_dns(ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "unknown"
