from typing import Protocol


class Scan(Protocol):
    @staticmethod
    def scan(target: str) -> dict:
        return {}
