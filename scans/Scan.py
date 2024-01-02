from abc import abstractmethod
from typing import Protocol


class Scan(Protocol):
    @abstractmethod
    def scan(target: str) -> dict:
        pass

    @abstractmethod
    def get_name() -> str:
        pass
