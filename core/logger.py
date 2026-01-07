import logging
import sys
from termcolor import colored

# Add TRACE level
TRACE_LEVEL_NUM = 5
logging.addLevelName(TRACE_LEVEL_NUM, "TRACE")

class ReasoningLogger:
    def __init__(self, debug=False):
        self.logger = logging.getLogger("RedReason")
        self.logger.setLevel(logging.DEBUG if debug else logging.INFO)
        self.verbosity = 0  # Track verbosity level (0=quiet, 1=normal, 2=verbose, 3+=trace)
        
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter('%(asctime)s - %(message)s', datefmt='%H:%M:%S')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        
        self.logs = [] # Store structural logs for the report

    def set_verbosity(self, level):
        """Set verbosity level (0=quiet, 1=normal, 2=verbose, 3+=trace)"""
        self.verbosity = level
        if level == 0:
            self.logger.setLevel(logging.WARNING)
        elif level == 1:
            self.logger.setLevel(logging.INFO)
        elif level == 2:
            self.logger.setLevel(logging.DEBUG)
        else:  # 3+
            self.logger.setLevel(TRACE_LEVEL_NUM)

    def _log(self, prefix, message, color, level=logging.INFO):
        formatted_message = f"[{colored(prefix, color)}] {message}"
        self.logger.log(level, formatted_message)
        self.logs.append({"type": prefix, "message": message, "raw": formatted_message})

    def trace(self, message):
        """Log trace-level detail (very verbose)"""
        self._log("TRACE", message, "white", TRACE_LEVEL_NUM)

    def hypothesis(self, message):
        """Log a hypothesis (e.g., 'Target might be vulnerable to AS-REP Roasting')"""
        self._log("HYPOTHESIS", message, "yellow")

    def evidence(self, message):
        """Log discovered evidence (e.g., 'User has DontReqPreAuth set')"""
        self._log("EVIDENCE", message, "cyan")

    def success(self, message):
        """Log a confirmed success/vulnerability"""
        self._log("SUCCESS", message, "green")

    def fail(self, message):
        """Log a failure or refutation of a hypothesis"""
        self._log("FAIL", message, "red")

    def info(self, message):
        """General information"""
        self.logger.info(f"[*] {message}")

    def debug(self, message):
        """Debug information"""
        self.logger.debug(f"[DEBUG] {message}")

# Singleton instance
log = ReasoningLogger()
