from core.module import RedReasonModule
from core.logger import log
import ldap3

class ADDefenseAwareness(RedReasonModule):
    def __init__(self, target, domain, user, password, hashes=None, enumeration_data=None):
        super().__init__()
        self.name = "ADDefenseAwareness"
        self.description = "Defensive Posture Awareness (CredGuard, EDR, Tiering)"
        self.target = target
        self.domain = domain
        self.user = user
        self.password = password
        self.hashes = hashes
        self.enumeration_data = enumeration_data
        self.conn = None

    def run(self, args=None):
        self.log_start()
        if self.connect():
            self.execute_maturity_flow()
        self.log_end()

    def connect(self):
        try:
            pass_str = self.password if self.password else "LM:NT Hashes"
            log.debug(f"Connecting to {self.target} as {self.user}...")
            
            server = ldap3.Server(self.target, get_info=ldap3.ALL)
            if self.hashes:
                lm, nt = self.hashes.split(':')
                self.conn = ldap3.Connection(server, user=f"{self.domain}\\{self.user}", password=nt, authentication=ldap3.NTLM)
            else:
                self.conn = ldap3.Connection(server, user=f"{self.domain}\\{self.user}", password=self.password, authentication=ldap3.NTLM)
            
            if self.conn.bind():
                log.info(f"Connected to LDAP service on {self.target}")
                return True
            else:
                log.fail(f"Failed to bind to LDAP: {self.conn.result}")
                return False
        except Exception as e:
            log.fail(f"Connection error: {e}")
            return False

    def stage_l0_presence(self):
        """L0: Check for Credential Guard & EDR Processes (Simulated)."""
        log.info("[L0] Checking for Defensive Controls (CredGuard, PPL)...")
        # Credential Guard: msDS-DeviceGuardCCIGuardStatus on Computer objects
        # 0 = Disabled, 1 = Enabled with UEFI lock, 2 = Enabled without lock
        try:
            search_filter = "(&(objectClass=computer)(msDS-DeviceGuardCCIGuardStatus=*))"
            self.conn.search(self.conn.server.info.other['defaultNamingContext'][0], search_filter, attributes=['dNSHostName', 'msDS-DeviceGuardCCIGuardStatus'])
            
            cg_count = 0
            for entry in self.conn.entries:
                status = int(entry['msDS-DeviceGuardCCIGuardStatus'].value)
                if status > 0:
                    cg_count += 1
                    
            if cg_count > 0:
                log.evidence(f"[L0] Credential Guard Enabled on {cg_count} hosts. LSASS dumping will be difficult.")
            else:
                log.info("[L0] No explicit Credential Guard markers found in AD.")
                
        except Exception as e:
            log.debug(f"Failed to check CredGuard: {e}")

    def stage_l1_misconfig(self):
        """L1: Check logical defenses like Tiered Administration (AdminSDHolder overlap)."""
        log.info("[L1] Analysis: Checking for Tiered Admin Model Gaps...")
        # A simple check: Are there "Workstation" admins in "Domain Admins"?
        # This requires deep group analysis. 
        # For PoC, we flag if 'AdminSDHolder' is customized (often key in tiered models).
        
        # We can re-check the ACL on AdminSDHolder if we had the ACL module logic here.
        pass

    def stage_l2_validation(self):
        """L2: Validate EDR presence via simple callback (Placeholder)."""
        log.info("[L2] Validation: (Placeholder) Safe EDR Evasion Check.")

    def stage_l3_execution(self):
        """L3: Execution: SKIPPED."""
        pass
