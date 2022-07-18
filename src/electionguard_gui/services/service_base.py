from abc import ABC


class ServiceBase(ABC):
    """Responsible for common functionality among ell components"""

    def init(self) -> None:
        self.expose()

    def expose(self) -> None:
        pass
