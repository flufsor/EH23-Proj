from typing import Protocol

from config import Config


class Scan(Protocol):
    @staticmethod
    def scan(config: Config, target: str) -> dict:
        return {}
