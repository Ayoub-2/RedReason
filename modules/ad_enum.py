from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, LEVEL
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5 import constants
from impacket.krb5.types import Principal
from impacket.ldap import ldaptypes
import datetime
from core.logger import log
from core.types import ADUser, ADComputer

class ADEnumerator:
    def __init__(self, target, domain, user, password, hashes=None):
        self.target = target
        self.domain = domain
        self.user = user
        self.password = password
        self.hashes = hashes
        self.conn = None
        self.collected_users = []
        self.collected_computers = []
        self.collected_dcs = []

    def connect(self):
        # Check if we have credentials
        if not self.password and not self.hashes:
            log.info("No credentials provided. Switching to Blind Kerberos Enumeration mode.")
            return False # Return False to skip standard LDAP connection, but we will handle this in run_all

        log.info(f"Connecting to LDAP server: {self.target}")
        try:
            server = Server(self.target, get_info=ALL)
            # Handle Hashes if provided (LM:NT)
            if self.hashes:
                log.hypothesis("Attempting Pass-the-Hash authentication...")
                # ldap3 supports NTLM hashes in the password field for NTLM authentication
                self.password = self.hashes
            
            self.conn = Connection(server, user=f"{self.domain}\\{self.user}", password=self.password, authentication=NTLM, auto_bind=True)
            log.success("LDAP Bind Successful")
            log.evidence(f"Connected to Domain: {server.info.other['defaultNamingContext'][0]}")
            return True
        except Exception as e:
            log.fail(f"LDAP Connection Failed: {e}")
            return False

    def get_naming_contexts(self):
        if not self.conn: return None, None
        default_nc = self.conn.server.info.other['defaultNamingContext'][0]
        config_nc = self.conn.server.info.other['configurationNamingContext'][0]
        return default_nc, config_nc

    def check_machine_account_quota(self):
        log.info("Checking Machine Account Quota...")
        default_nc, _ = self.get_naming_contexts()
        self.conn.search(default_nc, "(objectClass=domain)", attributes=['ms-DS-MachineAccountQuota'])
        
        for entry in self.conn.entries:
            quota = entry['ms-DS-MachineAccountQuota']
            if quota and int(quota.value) > 0:
                log.evidence(f"Machine Account Quota: {quota}")
                log.hypothesis("Any user can add machine accounts (potential for shadow credentials/relaying abuse).")
            else:
                log.info(f"Machine Account Quota check passed (Quota: {quota})")

    def check_password_policy(self):
        log.info("Checking Domain Password Policy...")
        default_nc, _ = self.get_naming_contexts()
        # Basic domain policy
        self.conn.search(default_nc, "(objectClass=domainDNS)", attributes=['minPwdLength', 'pwdProperties', 'lockoutThreshold'])
        for entry in self.conn.entries:
            log.evidence(f"Domain Password Policy: MinLength={entry.minPwdLength}, LockoutThreshold={entry.lockoutThreshold}")

    def get_domain_trusts(self):
        log.info("Enumerating Domain Trusts...")
        default_nc, _ = self.get_naming_contexts()
        self.conn.search(default_nc, "(objectClass=trustedDomain)", attributes=['flatName', 'name', 'trustDirection', 'trustType', 'trustAttributes'])
        
        if not self.conn.entries:
            log.info("No Domain Trusts found.")
        
        for entry in self.conn.entries:
            direction = entry.trustDirection
            dir_str = "Attributes: " + str(entry.trustAttributes)
            # 1=Inbound, 2=Outbound, 3=Bidirectional
            if direction == 1: dir_str = "Inbound"
            elif direction == 2: dir_str = "Outbound"
            elif direction == 3: dir_str = "Bidirectional"
            
            log.evidence(f"Trust Found: {entry.name} ({entry.flatName}) - {dir_str}")

    def get_group_members(self):
        log.info("Enumerating High-Value Group Members...")
        default_nc, _ = self.get_naming_contexts()
        target_groups = ["Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Remote Desktop Users", "Account Operators", "Backup Operators", "Server Operators", "Print Operators", "Group Policy Creator Owners"]
        
        for group in target_groups:
            self.conn.search(default_nc, f"(&(objectClass=group)(cn={group}))", attributes=['member'])
            for entry in self.conn.entries:
                members = entry.member
                if members:
                    log.evidence(f"Group '{group}' Members:")
                    for m in members:
                        log.evidence(f"  - {m}")
                else:
                    log.info(f"Group '{group}' has no members or could not be queried.")

    def check_laps(self):
        log.info("Checking for LAPS...")
        default_nc, _ = self.get_naming_contexts()
        # Checking for presence of ms-Mcs-AdmPwd attribute on computers could indicate LAPS usage
        # We try to read it. If we can see it, that's a huge finding.
        search_filter = "(&(objectCategory=computer)(ms-Mcs-AdmPwd=*))"
        try:
            self.conn.search(default_nc, search_filter, attributes=['dNSHostName', 'ms-Mcs-AdmPwd'])
            if self.conn.entries:
                for entry in self.conn.entries:
                    pwd = entry['ms-Mcs-AdmPwd']
                    if pwd:
                        log.success(f"VULNERABLE: LAPS Password Readable on {entry.dNSHostName}: {pwd}")
            else:
                log.info("No LAPS passwords readable (or LAPS not in use/no permissions).")
        except Exception as e:
            log.fail(f"LAPS check error: {e}")

    def check_adcs(self):
        log.info("Checking for AD CS (PKI)...")
        _, config_nc = self.get_naming_contexts()
        if not config_nc:
            log.fail("Could not get Configuration Naming Context for AD CS check.")
            return

        # Search for Enrollment Services in Configuration NC
        search_filter = "(objectClass=pKIEnrollmentService)"
        try:
            self.conn.search(config_nc, search_filter, search_scope=SUBTREE, attributes=['cn', 'dNSHostName', 'name'])
            if self.conn.entries:
                for entry in self.conn.entries:
                    log.evidence(f"AD CS CA Found: {entry.cn} on {entry.dNSHostName}")
                    log.hypothesis(f"Evaluate {entry.name} for ESC vectors (ESC1, ESC8).")
            else:
                log.info("No AD CS Certificate Authorities found via LDAP.")
        except Exception as e:
            log.fail(f"AD CS check error: {e}")

    def get_gpos(self):
        log.info("Enumerating Group Policy Objects...")
        default_nc, _ = self.get_naming_contexts()
        self.conn.search(default_nc, "(objectClass=groupPolicyContainer)", attributes=['displayName', 'gPCFileSysPath'])
        for entry in self.conn.entries:
            log.info(f"GPO: {entry.displayName} ({entry.gPCFileSysPath})")

    def get_users_detailed(self):
        log.info("Enumerating Users (Detailed)...")
        default_nc, _ = self.get_naming_contexts()
        # Users with descriptions often contain passwords
        self.conn.search(default_nc, "(&(objectClass=user)(objectCategory=person))", attributes=['sAMAccountName', 'description', 'pwdLastSet', 'badPwdCount', 'userAccountControl', 'adminCount', 'objectSid', 'distinguishedName'])
        
        for entry in self.conn.entries:
            name = str(entry.sAMAccountName)
            desc = entry.description
            pwd_ts = int(entry.pwdLastSet.value.timestamp()) if entry.pwdLastSet else 0
            uac = int(entry.userAccountControl.value) if entry.userAccountControl else 0
            
            user_obj = ADUser(
                name=name,
                dn=str(entry.distinguishedName),
                sid=str(entry.objectSid) if 'objectSid' in entry else "",
                description=str(desc) if desc else "",
                admin_count=bool(entry.adminCount.value) if entry.adminCount else False,
                password_last_set=pwd_ts,
                uac_flags=uac
            )

            # Store for BloodHound
            self.collected_users.append(user_obj)

            if desc:
                log.evidence(f"User '{name}' has a description: '{desc}'")
                log.hypothesis("Check description for passwords or sensitive information.")
            
            # Check for 'Don't Require Preauthentication' (AS-REP Roasting)
            # UAC_FLAG_DONT_REQUIRE_PREAUTH = 0x00040000
            if uac & 0x00040000:
                user_obj.is_roastable_asrep = True
                log.success(f"VULNERABLE: User '{name}' does NOT require Kerberos preauthentication (AS-REP Roasting possible).")

    def get_domain_controllers(self):
        log.info("Enumerating Domain Controllers...")
        default_nc, _ = self.get_naming_contexts()
        # Domain controllers are servers with the 'userAccountControl' bit for 'SERVER_TRUST_ACCOUNT' (0x2000) set
        # and also have the 'primaryGroupID' of 'Domain Controllers' (516)
        self.conn.search(default_nc, "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))", attributes=['dNSHostName', 'distinguishedName'])
        
        for entry in self.conn.entries:
            hostname = str(entry.dNSHostName)
            log.evidence(f"Domain Controller Found: {hostname}")
            self.collected_dcs.append(ADComputer(name=hostname.split('.')[0], dn=str(entry.distinguishedName), is_dc=True))

    def check_dcsync_rights(self):
        log.info("Checking for Suspect DCSync Rights...")
        default_nc, _ = self.get_naming_contexts()
        # Read the nTSecurityDescriptor of the Domain Root
        self.conn.search(default_nc, "(objectClass=domain)", attributes=['nTSecurityDescriptor'], search_scope=LEVEL)
        
        for entry in self.conn.entries:
            raw_sd = entry['nTSecurityDescriptor'].value
            if raw_sd:
                try:
                    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sd)
                    for ace in sd['Dacl'].aces:
                        # DS-Replication-Get-Changes (1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)
                        # DS-Replication-Get-Changes-All (1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)
                        DCSYNC_RIGHTS = [
                            '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
                            '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
                        ]
                        
                        try:
                            ace_type = ace['AceType']
                            # ACCESS_ALLOWED_OBJECT_ACE = 0x05
                            if ace_type == 0x05:
                                # Check if ObjectType is present (ACE_OBJECT_TYPE_PRESENT = 0x01)
                                if ace['Ace']['Flags'] & 0x01:
                                    # ObjectType is bytes, convert to string UUID
                                    import uuid
                                    obj_type_bytes = ace['Ace']['ObjectType']
                                    obj_uuid = str(uuid.UUID(bytes_le=obj_type_bytes))
                                    
                                    if obj_uuid in DCSYNC_RIGHTS:
                                        sid = ace['Ace']['Sid'].formatCanonical()
                                        log.evidence(f"DCSync Right Found! SID: {sid} has right {obj_uuid}")
                                        log.hypothesis(f"  -> Principal {sid} can replicate secrets (DCSync).")
                        except Exception as ex:
                            pass
                        
                    log.info("DCSync Rights Check: Parsed SD (Deep analysis skipped in this snippet to avoid complexity).")
                except Exception as e:
                    log.debug(f"Failed to parse Domain SD: {e}")

    def check_service_account_risks(self):
        log.info("Checking for High-Risk Service Accounts & Hygiene...")
        default_nc, _ = self.get_naming_contexts()
        
        # 1. Get all admins
        admins = set()
        for group in ["Domain Admins", "Enterprise Admins", "Administrators"]:
            self.conn.search(default_nc, f"(&(objectClass=group)(cn={group}))", attributes=['member'])
            for entry in self.conn.entries:
                for m in entry.member:
                    admins.add(str(m))

        # 2. Get users with SPNs + Hygiene Attributes
        self.conn.search(default_nc, "(&(objectClass=user)(servicePrincipalName=*))", attributes=['distinguishedName', 'sAMAccountName', 'pwdLastSet', 'adminCount'])
        
        current_time = datetime.datetime.now(datetime.timezone.utc)

        for entry in self.conn.entries:
            dn = str(entry.distinguishedName)
            name = str(entry.sAMAccountName)
            
            # Risk: Admin SPN
            if dn in admins:
                log.success(f"CRITICAL: Service Account {name} is a HIGH PRIVILEGE account!")
                log.hypothesis(f"Kerberoasting {name} could yield Domain Admin access.")
            
            # Hygiene: Password Age
            if entry.pwdLastSet:
                pwd_set = entry.pwdLastSet.value
                if pwd_set:
                    # ldap3 returns localized datetime, simple diff
                    age = (current_time - pwd_set).days
                    if age > 365:
                        log.evidence(f"Hygiene: Service Account {name} password is {age} days old.")

            # Hygiene: Shadow Admin (adminCount=1 but maybe not in DA)
            if entry.adminCount and int(entry.adminCount.value) == 1 and dn not in admins:
                 log.evidence(f"Hygiene: Service Account {name} has adminCount=1 (Potential old admin/Shadow Admin).")

    def check_kerberos_encryption_types(self):
        log.info("Checking Kerberos Encryption Types (Legacy Protocols)...")
        default_nc, _ = self.get_naming_contexts()
        # msDS-SupportedEncryptionTypes: 
        # 0x1F = RC4, AES128, AES256...
        # If value is 0 or 4 (RC4 only), it's weak.
        # We look for computers/users where (msDS-SupportedEncryptionTypes=4) or missing allows RC4 fallback
        
        self.conn.search(default_nc, "(&(objectClass=user)(msDS-SupportedEncryptionTypes=4))", attributes=['sAMAccountName'])
        for entry in self.conn.entries:
             log.evidence(f"Weak Crypto: User {entry.sAMAccountName} supports ONLY RC4 encryption.")

    def check_adminsdholder(self):
        log.info("Checking AdminSDHolder for Backdoors...")
        # Location: CN=AdminSDHolder,CN=System,DC=...
        _, config_nc = self.get_naming_contexts() # Not config, it's in System container of Default NC
        default_nc, _ = self.get_naming_contexts()
        system_dn = f"CN=System,{default_nc}"
        
        self.conn.search(system_dn, "(cn=AdminSDHolder)", attributes=['nTSecurityDescriptor'])
        for entry in self.conn.entries:
            # Primitive check: just logging existence for now. Deep parsing would check for unknown SIDs in DACL.
            log.info("AdminSDHolder object found. Manual review of ACLs recommended for persistence.")
            # Implementation of full SD parsing is complex for this snippet, but placeholder is here.

    def assess_remote_exposure(self):
        log.info("Assessing Remote Service Exposure (via SPNs)...")
        default_nc, _ = self.get_naming_contexts()
        # Map services to risks
        risky_services = {
            "TERMSRV": "RDP Access (Remote GUI)",
            "WSMAN": "WinRM Access (Remote Shell)",
            "MSSQLSvc": "SQL Server (Data/XP_CMDSHELL)",
            "CIFS": "File Sharing (SMB)"
        }
        
        for svc, risk in risky_services.items():
            filter_str = f"(&(objectClass=computer)(servicePrincipalName={svc}*))"
            self.conn.search(default_nc, filter_str, attributes=['dNSHostName'])
            count = len(self.conn.entries)
            if count > 0:
                log.info(f"Exposure: {count} hosts exposing {svc} ({risk}).")
                if count < 5: # List them if few
                    for e in self.conn.entries:
                        log.evidence(f"  - {e.dNSHostName}")

    def assess_spray_feasibility(self):
        log.info("Assessing Password Spray Feasibility...")
        default_nc, _ = self.get_naming_contexts()
        
        # 1. Check Policy
        lockout = 0
        self.conn.search(default_nc, "(objectClass=domainDNS)", attributes=['lockoutThreshold'])
        if self.conn.entries:
            l_val = self.conn.entries[0].lockoutThreshold
            if l_val: lockout = int(l_val.value)
        
        # 2. Count Users
        self.conn.search(default_nc, "(&(objectClass=user)(objectCategory=person))", attributes=['cn'])
        user_count = len(self.conn.entries)
        
        log.info(f"Policy: Lockout at {lockout} attempts. Domain has {user_count} users.")
        
        if (lockout == 0 or lockout > 5) and user_count > 50:
            log.success("VULNERABLE: Password Spraying is HIGHLY feasible (Weak Lockout + High User Count).")
        else:
            log.info("Password Spraying risk is moderate/low.")

    def check_adcs_templates(self):
        log.info("Checking AD CS Certificate Templates (ESC1)...")
        # Search for templates
        # Configuration Naming Context is needed for templates: CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=...
        _, config_nc = self.get_naming_contexts()
        pkis_dn = f"CN=Public Key Services,CN=Services,{config_nc}"
        
        self.conn.search(pkis_dn, "(objectClass=pKICertificateTemplate)", attributes=['name', 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag', 'pKIExtendedKeyUsage'])
        
        for entry in self.conn.entries:
            name = str(entry.name)
            name_flag = int(entry['msPKI-Certificate-Name-Flag'].value or 0)
            enroll_flag = int(entry['msPKI-Enrollment-Flag'].value or 0)
            ekus = entry['pKIExtendedKeyUsage'].value or []
            
            # ESC1 Conditions:
            # 1. Enrollee Supplies Subject (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001)
            # 2. Client Authentication EKU (1.3.6.1.5.5.7.3.2) or Smart Card Logon (1.3.6.1.4.1.311.20.2.2) or Any Purpose (2.5.29.37.0)
            # 3. Manager Approval NOT required (CT_FLAG_PEND_ALL_REQUESTS = 0x00000002) - If set, it's safer.
            
            is_enrollee_supplies_subject = (name_flag & 0x00000001) > 0
            requires_approval = (enroll_flag & 0x00000002) > 0
            
            has_auth_eku = False
            for eku in ekus:
                if eku in ['1.3.6.1.5.5.7.3.2', '1.3.6.1.4.1.311.20.2.2', '2.5.29.37.0']:
                    has_auth_eku = True
                    break
            
            if is_enrollee_supplies_subject and has_auth_eku and not requires_approval:
                log.success(f"VULNERABLE (ESC1): Template '{name}' allows 'Enrollee Supplies Subject' + Client Auth!")
                log.hypothesis(f"  -> An attacker can request a cert as ANY user (e.g. Administrator) using this template.")

    def check_adcs_web_enrollment(self):
        log.info("Checking for AD CS Web Enrollment (ESC8)...")
        # Check pKIEnrollmentService in Configuration partition
        _, config_nc = self.get_naming_contexts()
        pkis_dn = f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_nc}"
        
        self.conn.search(pkis_dn, "(objectClass=pKIEnrollmentService)", attributes=['dNSHostName', 'name'])
        
        for entry in self.conn.entries:
            host = str(entry.dNSHostName)
            ca_name = str(entry.name)
            # We can't confirm HTTP endpoint existence purely via LDAP, but existence of an Enrollment Service often implies it.
            # Real validation would verify http://<host>/certsrv
            log.evidence(f"CA Found: {ca_name} on {host}")
            log.hypothesis(f"  -> Check http://{host}/certsrv for ESC8 (NTLM Relay to AD CS).")


            log.hypothesis(f"  -> Check http://{host}/certsrv for ESC8 (NTLM Relay to AD CS).")

    def get_computers_basic(self):
        # We need this for BloodHound even if not logging explicitly
        default_nc, _ = self.get_naming_contexts()
        self.conn.search(default_nc, "(objectClass=computer)", attributes=['dNSHostName', 'distinguishedName'])
        for entry in self.conn.entries:
             self.collected_computers.append(ADComputer(
                 name=str(entry.dNSHostName).split('.')[0],
                 dn=str(entry.distinguishedName)
             ))

    def verify_user_kerberos(self):
        log.info(f"Attempting to verify user '{self.user}' via Kerberos (Port 88)...")
        if not self.user:
            log.fail("Cannot perform blind enumeration without a username (--user).")
            return

        try:
            clientName = Principal(self.user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            # Request TGT with NO Pre-Auth (checking if user exists or is roastable)
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(clientName, '', self.domain, None, None, no_preauth=True)
            
            # If we get here, we got a TGT! 
            log.success(f"User '{self.user}' EXISTS and is VULNERABLE to AS-REP Roasting! (TGT received without password)")
            # Create a partial ADUser
            self.collected_users.append(ADUser(name=self.user, is_roastable_asrep=True))
            
        except Exception as e:
            error_msg = str(e)
            if "KDC_ERR_PREAUTH_REQUIRED" in error_msg or "SessionError: KDC_ERR_PREAUTH_REQUIRED" in error_msg:
                log.success(f"User '{self.user}' EXISTS! (Pre-Auth Required)")
                self.collected_users.append(ADUser(name=self.user))
            elif "KDC_ERR_C_PRINCIPAL_UNKNOWN" in error_msg:
                log.fail(f"User '{self.user}' DOES NOT EXIST.")
            else:
                log.info(f"User '{self.user}' Verification Result: {error_msg}")


    def run_all(self):
        # If credentials exist, try LDAP
        if self.password or self.hashes:
            if self.connect():
                self.get_computers_basic() # Populate list
                self.check_machine_account_quota()
                self.check_password_policy()
                self.get_domain_trusts()
                self.get_group_members()
                self.get_users_detailed()
                self.get_domain_controllers()
                self.check_laps()
                self.check_adcs()
                self.check_adcs_templates()
                self.check_adcs_web_enrollment()
                self.get_gpos()
                self.check_dcsync_rights()
                self.check_service_account_risks()
                self.check_kerberos_encryption_types()
                self.check_adminsdholder()
                self.assess_remote_exposure()
                self.assess_spray_feasibility()
                log.info("Enumeration complete")
        else:
            # Fallback to blind enumeration
            self.verify_user_kerberos()

def run(args):
    # Wrapper for main.py
    enumerator = ADEnumerator(args.target, args.domain, args.user, args.password, args.hashes)
    enumerator.run_all()
