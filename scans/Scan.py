from abc import ABC, abstractmethod


class Scan(ABC):
    @abstractmethod
    def __init__(self, target: str):
        self.target = target

    @abstractmethod
    def scan(self) -> dict:
        pass

    @abstractmethod
    def get_name(self) -> str:
        pass
