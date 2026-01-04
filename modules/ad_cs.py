from core.module import RedReasonModule
from core.logger import log
import ldap3

class ADCSAbuse(RedReasonModule):
    def __init__(self, target, domain, user, password, hashes=None, enumeration_data=None):
        super().__init__()
        self.name = "ADCSAbuse"
        self.description = "ADCS Abuse & Misconfiguration (ESC1, ESC8, Templates)"
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
                self.config_nc = self.conn.server.info.other['configurationNamingContext'][0]
                return True
            else:
                log.fail(f"Failed to bind to LDAP: {self.conn.result}")
                return False
        except Exception as e:
            log.fail(f"Connection error: {e}")
            return False

    def stage_l0_presence(self):
        """L0: Check for Enterprise CAs and Enrollment Services."""
        log.info("[L0] Checking for AD CS Infrastructure...")
        try:
            # Search for pKIEnrollmentService in Configuration Naming Context
            # CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration...
            search_base = f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{self.config_nc}"
            self.conn.search(search_base, "(objectClass=pKIEnrollmentService)", attributes=['cn', 'dNSHostName'])
            
            if self.conn.entries:
                log.success(f"[L0] Validated: Found {len(self.conn.entries)} Enterprise CA(s).")
                for entry in self.conn.entries:
                    log.evidence(f"CA Found: {entry.cn} on {entry.dNSHostName}")
            else:
                log.info("[L0] No Enterprise CAs found via LDAP.")
                
        except Exception as e:
            log.fail(f"[L0] Error checking AD CS presence: {e}")

    def stage_l1_misconfig(self):
        """L1: Check for Certificate Templates with vulnerable configurations (ESC1)."""
        log.info("[L1] Identifying vulnerable Certificate Templates (ESC1)...")
        # Search for templates that allow Client Authentication and have CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
        try:
            # CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration...
            search_base = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{self.config_nc}"
            
            # Logic roughly:
            # 1. Get all templates
            # 2. Check msPKI-Certificate-Name-Flag (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x1)
            # 3. Check pKIExtendedKeyUsage (Client Auth = 1.3.6.1.5.5.7.3.2 or Smart Card Logon)
            # 4. Check Enrollment Rights (ACLs) - This requires heavy SD parsing, simplified here for PoC
            
            self.conn.search(search_base, "(objectClass=pKICertificateTemplate)", attributes=['cn', 'msPKI-Certificate-Name-Flag', 'pKIExtendedKeyUsage'])
            
            for entry in self.conn.entries:
                try:
                    name_flags = int(entry['msPKI-Certificate-Name-Flag'].value) if entry['msPKI-Certificate-Name-Flag'] else 0
                    ekus = entry['pKIExtendedKeyUsage'].value if entry['pKIExtendedKeyUsage'] else []
                    
                    is_enrollee_supplies_subject = (name_flags & 0x1)
                    has_client_auth = False
                    
                    # Check EKUs (can be list or single string)
                    if isinstance(ekus, str): ekus = [ekus]
                    for eku in ekus:
                        if eku in ['1.3.6.1.5.5.7.3.2', '1.3.6.1.4.1.311.20.2.2']: # Client Auth or Smart Card Logon
                            has_client_auth = True
                            
                    if is_enrollee_supplies_subject and has_client_auth:
                        log.evidence(f"[L1] Potential ESC1 Template Found: {entry.cn} (Enrollee Supplies Subject + Client Auth)")
                        log.hypothesis(f"Template {entry.cn} might allow arbitrary user impersonation if enrollment rights exist.")
                        
                except Exception as inner_e:
                    continue

        except Exception as e:
            log.fail(f"[L1] Error analyzing templates: {e}")

    def stage_l2_validation(self):
        """L2: Validate enrollment rights (Requires resolving SD against current user)."""
        log.info("[L2] Validation: (Placeholder) Validating enrollment rights on found templates.")

    def stage_l3_execution(self):
        """L3: Execution: Request Malicious Cert (SKIP)."""
        log.success("[L3] Execution: SKIPPED (Requires explicit --exploit flag). Safe Mode.")
