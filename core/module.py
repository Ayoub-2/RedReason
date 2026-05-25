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
        self.max_level = 3  # Dynamic execution ceiling boundary

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

    # ==========================================
    # Module Maturity Model (L0 - L3)
    # ==========================================
    
    def stage_l0_presence(self):
        """L0: Check if the feature/service exists."""
        pass

    def stage_l1_misconfig(self):
        """L1: Check for dangerous configurations."""
        pass

    def stage_l2_validation(self):
        """L2: Validate exploitability (non-intrusive)."""
        pass

    def stage_l3_execution(self):
        """L3: Execute the attack (Requires explicit mode)."""
        pass

    def execute_maturity_flow(self):
        """
        Executes the module stages in order, respecting the max_level boundary.
        """
        log.info(f"[{self.name}] Initiating Maturity Flow (Ceiling: L{self.max_level})")
        if self.max_level >= 0:
            self.stage_l0_presence()
        if self.max_level >= 1:
            self.stage_l1_misconfig()
        if self.max_level >= 2:
            self.stage_l2_validation()
        if self.max_level >= 3:
            self.stage_l3_execution()

