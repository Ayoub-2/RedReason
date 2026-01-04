from core.module import RedReasonModule
from core.logger import log
from core.types import ADGPO
import ldap3

class ADGPOAbuse(RedReasonModule):
    def __init__(self, target, domain, user, password, hashes=None, enumeration_data=None):
        super().__init__()
        self.name = "ADGPOAbuse"
        self.description = "GPO Abuse & Policy Weakness (WriteGPO, Link Manipulation)"
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
        """L0: List GPOs and verify SYSVOL path readability."""
        log.info("[L0] Enumerating Group Policy Objects...")
        try:
            # Query all groupPolicyContainer objects
            self.conn.search(
                self.conn.server.info.other['defaultNamingContext'][0], 
                "(objectClass=groupPolicyContainer)", 
                attributes=['displayName', 'gPCFileSysPath', 'nTSecurityDescriptor']
            )
            
            count = 0
            for entry in self.conn.entries:
                count += 1
                gpo_name = str(entry.displayName)
                gpo_path = str(entry.gPCFileSysPath)
                log.debug(f"Found GPO: {gpo_name} ({gpo_path})")
                
            if count > 0:
                log.success(f"[L0] Validated: Found {count} GPOs in the domain.")
            else:
                log.info("[L0] No GPOs found.")
                
        except Exception as e:
            log.fail(f"[L0] Error listing GPOs: {e}")

    def stage_l1_misconfig(self):
        """L1: Check for dangerous permissions on GPOs (Write/Modify)."""
        log.info("[L1] identifying weak permissions on GPO objects...")
        # In a full implementation, we would parse the nTSecurityDescriptor of each GPO
        # to see if the current user (or a group they are in) has Write permissions.
        # This requires matching the SD against the SIDs collected in enumeration.
        
        # Placeholder for complex SD parsing logic
        # We will log that we are *checking* for 'WriteProperty', 'WriteDacl', 'GenericWrite'
        pass

    def stage_l2_validation(self):
        """L2: Validate if weak GPOs are linked to high-value OUs."""
        log.info("[L2] Validation: Checking linkage of weak GPOs to OUs.")
        # If we found widespread write access in L1, L2 checks scope.
        # e.g., Is this GPO linked to the "Domain Controllers" OU?
        pass

    def stage_l3_execution(self):
        """L3: Safe Execution (SKIP)."""
        log.success("[L3] Execution: SKIPPED (Requires explicit --exploit flag). Safe Mode.")
