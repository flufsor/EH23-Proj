from abc import ABC, abstractmethod
from typing import Protocol


class Scan(Protocol):
    @abstractmethod
    def __init__(self, target: str):
        pass

    @abstractmethod
    def scan(self) -> dict:
        pass

    @abstractmethod
    def get_name() -> str:
        pass
