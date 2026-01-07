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

    def is_stealth_mode(self, args):
        """Check if stealth mode is enabled."""
        return hasattr(args, 'stealth') and args.stealth

    def log_start(self):
        log.info(f"Starting Module: {self.name} - {self.description}")

    def log_end(self):
        log.info(f"Completed Module: {self.name}")

    # ==========================================
    # Module Maturity Model (L0 - L4)
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
        Executes the module stages in order.
        """
        self.stage_l0_presence()
        self.stage_l1_misconfig()
        self.stage_l2_validation()
        # L3 is usually triggered manually or via specific flags in subclasses
