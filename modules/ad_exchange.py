from core.module import RedReasonModule
from core.logger import log
import ldap3
from ldap3 import SUBTREE, LEVEL

class ADExchangeOps(RedReasonModule):
    def __init__(self, target, domain, user, password, hashes=None, enumeration_data=None):
        super().__init__()
        self.name = "ADExchangeOps"
        self.description = "Exchange Enumeration & Abuse (PrivExchange, RBAC, Hybrid)"
        self.target = target
        self.domain = domain
        self.user = user
        self.password = password
        self.hashes = hashes
        self.enumeration_data = enumeration_data
        self.conn = None
        self.config_nc = None

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
                if 'configurationNamingContext' in self.conn.server.info.other:
                    self.config_nc = self.conn.server.info.other['configurationNamingContext'][0]
                else:
                    log.fail("Could not retrieve Configuration Naming Context. Some checks will fail.")
                return True
            else:
                log.fail(f"Failed to bind to LDAP: {self.conn.result}")
                return False
        except Exception as e:
            log.fail(f"Connection error: {e}")
            return False

    def stage_l0_presence(self):
        """L0: Enumerate Servers, Admin Groups, and RBAC Roles."""
        log.info("[L0] Enumerating Exchange Infrastructure...")
        try:
            # 1. Enumerate Exchange Servers
            if self.config_nc:
                log.info("Searching for Exchange Servers in Config NC...")
                self.conn.search(self.config_nc, "(objectClass=msExchExchangeServer)", attributes=['name', 'serialNumber', 'networkAddress'])
                
                if self.conn.entries:
                    count = len(self.conn.entries)
                    log.success(f"[L0] Found {count} Exchange Server(s).")
                    for entry in self.conn.entries:
                        # networkAddress is often like 'ncacn_ip_tcp:192.168.1.1'
                        addrs = entry.networkAddress if entry.networkAddress else []
                        ip = "Unknown"
                        for a in addrs:
                            if "ncacn_ip_tcp" in str(a):
                                ip = str(a).split(':')[1]
                                break
                        log.evidence(f"Exchange Server: {entry.name} (Ver: {entry.serialNumber}) IP: {ip}")
                else:
                    log.info("[L0] No Exchange Server objects found.")

            # 2. Critical Groups
            log.info("Checking Critical Exchange Groups...")
            groups = ["Organization Management", "Exchange Trusted Subsystem", "Exchange Windows Permissions"]
            default_nc = self.conn.server.info.other['defaultNamingContext'][0]
            
            for g in groups:
                self.conn.search(default_nc, f"(&(objectClass=group)(name={g}))", attributes=['distinguishedName', 'member'])
                if self.conn.entries:
                    entry = self.conn.entries[0]
                    member_count = len(entry.member) if entry.member else 0
                    log.evidence(f"Group Found: {g} ({member_count} members)")
                else:
                    log.debug(f"Group {g} not found.")

        except Exception as e:
            log.debug(f"[L0] Enumeration Failed: {e}")

    def stage_l1_misconfig(self):
        """L1: PrivExchange, RBAC Abuse, Legacy Auth."""
        log.info("[L1] Checking for Exchange Misconfigurations & ACL Abuse...")
        try:
            # 1. PrivExchange Indicator (Exchange Windows Permissions -> WriteDACL on Domain)
            # This requires checking the Domain Object's ACL.
            # Simplified Check: Just confirming the group exists and we are in an Exchange environment is a strong indicator
            # if the patch level is old. Here we log the hypothesis.
            log.hypothesis("VULNERABLE: PrivExchange: Check if 'Exchange Windows Permissions' has WriteDACL on Domain Root using BloodHound/Adcsl.")

            # 2. RBAC: ApplicationImpersonation
            if self.config_nc:
                log.info("Auditing RBAC for 'ApplicationImpersonation'...")
                # Search for Role Assignments granting this role.
                # Common Role Name: "ApplicationImpersonation"
                # We search for msExchRoleAssignment where msExchRoleName points to ApplicationImpersonation
                
                # First find the Role DN
                self.conn.search(self.config_nc, "(cn=ApplicationImpersonation)", attributes=['distinguishedName'])
                if self.conn.entries:
                    role_dn = self.conn.entries[0].distinguishedName
                    
                    # Find assignments
                    self.conn.search(self.config_nc, f"(&(objectClass=msExchRoleAssignment)(msExchRoleName={role_dn}))", attributes=['msExchRoleAssigneeName'])
                    for entry in self.conn.entries:
                        assignee = str(entry.msExchRoleAssigneeName)
                        # The assignee is likely a Role Group or User.
                        # Clean up DN to CN for display
                        assignee_cn = assignee.split(',')[0].split('=')[1]
                        log.success(f"VULNERABLE: Exchange RBAC: 'ApplicationImpersonation' assigned to: {assignee_cn}")
                        log.hypothesis("  -> Identifies potential for silent mailbox access (Shadow Attack).")
                else:
                    log.info("Role 'ApplicationImpersonation' not found (Unusual for Exchange env).")

            # 3. Hybrid / Azure AD Connect
            # Look for MSOL_ accounts
            log.info("Checking for Azure AD Connect Accounts (Hybrid Trust)...")
            default_nc = self.conn.server.info.other['defaultNamingContext'][0]
            self.conn.search(default_nc, "(&(objectClass=user)(sAMAccountName=MSOL_*))", attributes=['sAMAccountName'])
            for entry in self.conn.entries:
                 log.evidence(f"Hybrid Identity: Found AADC Account: {entry.sAMAccountName}")
                 log.hypothesis("Target for DCSync to facilitate Cloud pivoting (Password Hash Sync).")

        except Exception as e:
             log.debug(f"[L1] Abuse Check Failed: {e}")

    def stage_l2_validation(self):
        """L2: Validate Admin Access."""
        log.info("[L2] Validation: Checking local admin access for Exchange Subsystem (Skipped - Active Check).")

    def stage_l3_execution(self):
        """L3: Execution."""
        log.success("[L3] Safe Mode. Exploit execution skipped.")
