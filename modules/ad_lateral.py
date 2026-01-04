from core.module import RedReasonModule
from core.logger import log
import ldap3

class ADLateralMovement(RedReasonModule):
    def __init__(self, target, domain, user, password, hashes=None, enumeration_data=None):
        super().__init__()
        self.name = "ADLateralMovement"
        self.description = "Lateral Movement Exposure (LAPS, WinRM/RDP SPNs, Signing)"
        self.target = target
        self.domain = domain
        self.user = user
        self.password = password
        self.hashes = hashes
        self.enumeration_data = enumeration_data

    def run(self, args=None):
        self.log_start()
        # Connection is handled in shared state or established if needed. 
        # For this passive module, we heavily rely on enumeration data.
        self.execute_maturity_flow()
        self.log_end()

    def stage_l0_presence(self):
        """L0: Check Service Exposure via SPNs (WinRM, RDP)."""
        log.info("[L0] Analysis: Mapping Lateral Movement Protocols via SPNs...")
        if not self.enumeration_data or not self.enumeration_data.collected_computers:
            log.info("[L0] No computer cache found. Skipping passive SPN mapping.")
            return

        winrm_count = 0
        rdp_count = 0
        mssql_count = 0

        # We need SPNs. If not collected in basic enum, we might need to re-query, 
        # but ADComputer object *should* ideally have 'servicePrincipalName'.
        # Assuming ADComputer has a 'properties' dict with 'spn' list or similar if expanded.
        # In current types.py, ADComputer doesn't strictly hold full SPN list by default 
        # unless populated specifically. 
        # For now, we will assume we might need to query if not present, OR mostly likely
        # we update this to be a "Check" that runs queries if data missing.
        
        # Simulating finding based on typical environment
        log.info(" (Logic requires full SPN population in cache - Placeholder for PoC)")
        pass

    def stage_l1_misconfig(self):
        """L1: LAPS Distribution & SMB Signing (Inferred)."""
        log.info("[L1] Analysis: Checking LAPS Coverage & Signing defaults...")
        
        if not self.enumeration_data or not self.enumeration_data.collected_computers:
            return

        total_computers = len(self.enumeration_data.collected_computers)
        laps_enabled = 0
        server_os_count = 0
        
        for comp in self.enumeration_data.collected_computers:
            if comp.has_laps:
                laps_enabled += 1
            
            # Simple heuristic for Server OS
            if comp.os and "server" in comp.os.lower():
                server_os_count += 1

        # LAPS Coverage
        if total_computers > 0:
            coverage = (laps_enabled / total_computers) * 100
            log.info(f"LAPS Usage: {laps_enabled}/{total_computers} ({coverage:.1f}%)")
            
            if coverage < 50:
                 log.evidence("[L1] Low LAPS Coverage: Lateral movement via local admin credential Reuse is likely feasible.")
            else:
                 log.success("[L1] LAPS is widely deployed. Local Admin reuse attacks may be difficult.")
        
        # SMB Signing Inference
        # Servers usually require it, workstations don't.
        # This is a passive inference. Active check is better (in ad_attacks).
        if server_os_count < total_computers:
             workstations = total_computers - server_os_count
             log.evidence(f"[L1] Signing Exposure: {workstations} potential workstations likely have SMB Signing DISABLED (default).")

    def stage_l2_validation(self):
        """L2: Validate Admin Access (Requires Active Check/Relay)."""
        log.info("[L2] Validation: (Placeholder) Relay feasibility would be validated here via active probe.")

    def stage_l3_execution(self):
        """L3: Execution: SKIPPED."""
        pass
