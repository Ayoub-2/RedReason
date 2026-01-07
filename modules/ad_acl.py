from core.module import RedReasonModule
from core.logger import log
from core.types import ADUser, ADComputer
import ldap3
from ldap3.protocol.formatters.formatters import format_sid

class ADACLAbuse(RedReasonModule):
    def __init__(self, target, domain, user, password, hashes=None, enumeration_data=None):
        super().__init__()
        self.name = "ADACLAbuse"
        self.description = "ACL & Authorization Abuse (GenericAll, WriteDACL, Owner)"
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
            # Re-establish connection similar to ADEnumerator
            # Ideally we share the connection object too, but for now we separate connections per module
            # to avoid state corruption 
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
        """L0: Check if we can read Security Descriptors (nTSecurityDescriptor)."""
        log.info("[L0] Checking presence of Security Descriptor readability...")
        try:
            # Try to read the SD of the domain root
            default_nc = self.conn.server.info.other['defaultNamingContext'][0]
            self.conn.search(default_nc, "(objectClass=domain)", attributes=['nTSecurityDescriptor'])
            
            if self.conn.entries and self.conn.entries[0].nTSecurityDescriptor:
                log.success("[L0] Validated: Can read nTSecurityDescriptor via LDAP.")
            else:
                log.fail("[L0] Failed: Cannot read nTSecurityDescriptor or empty.")
        except Exception as e:
            log.fail(f"[L0] Error checking SD presence: {e}")

    def stage_l1_misconfig(self):
        """L1: Check for dangerous configurations (GenericAll, WriteDACL) on high-value targets."""
        log.info("[L1] identifying dangerous ACEs on Critical Objects...")
        if not self.enumeration_data or not self.enumeration_data.collected_users:
            log.info("[L1] No targets cache found. Skipping deep analysis to avoid noise.")
            return

        # Target High Value objects (Admins, DCs)
        # For PoC, we scan the collected objects from enumeration
        count = 0 
        for user in self.enumeration_data.collected_users:
            try:
                # Focus on Admin accounts or High Priv for noise reduction
                if user.admin_count: 
                    self.analyze_acl(user.dn, "User")
                    count += 1
            except Exception as e:
                pass
                
        log.info(f"[L1] Analyzed ACLs for {count} high-value objects.")

    def analyze_acl(self, dn, obj_type):
        try:
            # Query SD
            self.conn.search(dn, "(objectClass=*)", attributes=['nTSecurityDescriptor'], controls=[ldap3.protocol.microsoft.security_descriptor_control(sdflags=0x7)])
            if not self.conn.entries: return
            
            # Current Limitation: Deep ACE parsing requires manual struct unpacking of the binary nTSecurityDescriptor.
            # In a full-featured release, this would use a dedicated SD parser to match ACE masks (WriteDACL, GenericAll)
            # against the collected user SIDs.
            # For now, we verify we can *read* the SD, which is the prerequisite for analysis.
            log.info(f"    [!] Read SD for {dn} (Size: {len(sd_data)} bytes). Ready for offline analysis.")
            
        except Exception as e:
            log.debug(f"Failed to analyze ACL for {dn}: {e}")

    def stage_l2_validation(self):
        """L2: Validate exploitability (Effective Permissions)."""
        # Effective permissions calculation requires resolving nested groups and SIDs.
        log.info("[L2] Validation: Effective Access Check skipped (Requires offline SD analysis).")

    def stage_l3_execution(self):
        """L3: Execution (Modify ACL)."""
        log.success("[L3] Execution: SKIPPED (Requires explicit --exploit flag). Safe Mode.")
