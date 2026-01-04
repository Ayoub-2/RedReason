from abc import ABC, abstractmethod
from core.logger import log

class RedReasonModule(ABC):
    """
    Base interface for all RedReason modules.
    Ensures extensibility and consistent execution flow.
    """
    
    def __init__(self):
        self.name = "BaseModule"
        self.description = "Abstract Base Module"

    @abstractmethod
    def run(self, args):
        """
        Execute the module logic.
        :param args: Parsed command line arguments
        """
        pass

    def log_start(self):
        log.info(f"Starting Module: {self.name} - {self.description}")

    def log_end(self):
        log.info(f"Completed Module: {self.name}")
