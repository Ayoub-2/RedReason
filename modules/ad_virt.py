from core.module import RedReasonModule
from core.logger import log
import ldap3
import http.client
import ssl
import re

class ADVirtualizationOps(RedReasonModule):
    def __init__(self, target, domain, user, password, hashes=None, enumeration_data=None):
        super().__init__()
        self.name = "ADVirtualizationOps"
        self.description = "Virtualization Abuse (ESXi/vCenter, CVE-2024-37085)"
        self.target = target
        self.domain = domain
        self.user = user
        self.password = password
        self.hashes = hashes
        self.enumeration_data = enumeration_data
        self.conn = None
        
        # State
        self.esx_admins_group = None
        self.virtual_hosts = [] # List of dicts: {dn, name, ip, operatingSystem, spn}
        self.fingerprinted_hosts = {} # Map IP -> Version String

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
        """L0: Active & Passive Enumeration of Virtualization Infrastructure."""
        log.info("[L0] Enumerating Virtualization Infrastructure & 'ESX Admins'...")

        try:
            # 1. Check for 'ESX Admins' group
            self.conn.search(self.conn.server.info.other['defaultNamingContext'][0], 
                             "(&(objectClass=group)(cn=ESX Admins))", 
                             attributes=['cn', 'member', 'objectSid'])
            if self.conn.entries:
                self.esx_admins_group = self.conn.entries[0]
                log.success(f"[L0] Found Critical Group: '{self.esx_admins_group.cn}'")
                log.info(f"    Members: {len(self.esx_admins_group.member)}")
            else:
                log.info("[L0] 'ESX Admins' group NOT found (Potential CVE-2024-37085 Type 2 vector).")

            # 2. Enumerate ESXi/vCenter Hosts via LDAP (Passive)
            # Look for 'ESXi' in OS or 'vmware'/'esx' related SPNs
            ldap_filter = "(|(&(objectClass=computer)(operatingSystem=*ESXi*))(&(objectClass=computer)(servicePrincipalName=*host/esx*))(&(objectClass=computer)(servicePrincipalName=*vmware*)))"
            self.conn.search(self.conn.server.info.other['defaultNamingContext'][0], ldap_filter, attributes=['cn', 'dNSHostName', 'operatingSystem', 'servicePrincipalName', 'ipv4Address']) # ipv4Address might not always be populated in AD
            
            if self.conn.entries:
                log.success(f"[L0] Found {len(self.conn.entries)} likely Virtualization Host(s) in AD.")
                for entry in self.conn.entries:
                    host_info = {
                        'dn': entry.entry_dn,
                        'name': str(entry.cn),
                        'dns': str(entry.dNSHostName) if entry.dNSHostName else "",
                        'os': str(entry.operatingSystem) if entry.operatingSystem else "Unknown",
                        'spn': entry.servicePrincipalName.value if entry.servicePrincipalName else []
                    }
                    self.virtual_hosts.append(host_info)
                    log.evidence(f"Host: {host_info['name']} ({host_info['dns']}) | OS: {host_info['os']}")
            else:
                log.info("[L0] No Virtualization Hosts found via LDAP filters.")

            # 3. Active SOAP Fingerprinting (inspired by vmware_scanner)
            if self.virtual_hosts:
                log.info(f"[L0] Performing Active SOAP Fingerprinting on {len(self.virtual_hosts)} hosts...")
                for host in self.virtual_hosts:
                    self._soap_fingerprint(host)

        except Exception as e:
            log.fail(f"[L0] Enumeration Error: {e}")

    def _soap_fingerprint(self, host):
        """Send a SOAP request to /sdk/vimService to get version info."""
        target_host = host['dns'] if host['dns'] else host['name']
        if not target_host: return

        soap_msg = '''<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><soapenv:Body><RetrieveServiceContent xmlns="urn:vim25"><_this type="ServiceInstance">ServiceInstance</_this></RetrieveServiceContent></soapenv:Body></soapenv:Envelope>'''
        
        try:
            # Create unverified context
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            conn = http.client.HTTPSConnection(target_host, port=443, timeout=3, context=ctx)
            conn.request("POST", "/sdk/vimService", soap_msg, {"Content-type": "application/soap+xml"})
            resp = conn.getresponse()
            data = resp.read().decode('utf-8', errors='ignore')
            conn.close()

            if "VMware" in data:
                # Simple extraction, regex is safer than xml parsing for malformed data
                match = re.search(r"<fullName>(.*?)</fullName>", data)
                if match:
                    version = match.group(1)
                    self.fingerprinted_hosts[target_host] = version
                    log.evidence(f"Fingerprint ({target_host}): {version}")
                else:
                    log.evidence(f"Fingerprint ({target_host}): VMware Service Detected (Version Unknown)")
        except Exception as e:
            log.debug(f"Fingerprint failed for {target_host}: {e}")


    def stage_l1_misconfig(self):
        """L1: Identify 'ESX Admins' Abuse (CVE-2024-37085) and RCEs."""
        log.info("[L1] Analyzing for CVE-2024-37085 & Critical RCEs...")

        # CVE-2024-37085: Authentication Bypass / Group Hijack
        if self.esx_admins_group:
            # Case 1: Group Exists. Check control.
            log.info("[L1] 'ESX Admins' group exists. Checking privileges...")
            # In production, this would trigger an ACL analysis module (e.g., ad_acl) to verify write access.
            # For now, we flag it as a high-value target based on presence.
            
            log.hypothesis("VULNERABLE: CVE-2024-37085 (Type 1): If you can modify 'ESX Admins', you gain root on all domain-joined ESXi hosts.")
        
        elif self.virtual_hosts:
             # Case 2: Hosts exist, but group does not. (Shadow Admin)
             log.success("VULNERABLE: CVE-2024-37085 (Type 2): 'ESX Admins' group is MISSING but ESXi hosts exist.")
             log.hypothesis("Attacker with 'Create Group' rights can create 'ESX Admins' to instantly gain root access to discovered ESXi hosts.")

        # Vulnerability Correlation (Versioning)
        for host, version in self.fingerprinted_hosts.items():
            self._check_version_vulns(host, version)

    def _check_version_vulns(self, host, version):
        """Cross-reference version string with known critical CVEs."""
        # Simple string matching for PoC. In production, parse major/minor/build.
        
        # CVE-2021-21972 (vCenter 6.5 < 6.5 U3n, 6.7 < 6.7 U3l, 7.0 < 7.0 U1c)
        if "vCenter" in version:
             if "6.5" in version or "6.7" in version or "7.0.0" in version: # Rough check
                 log.evidence(f"[L1] {host}: Version '{version}' MAY be vulnerable to CVE-2021-21972 (Critical RCE).")

        # CVE-2024-37079/37080 (vCenter 7.0/8.0 unpatched)
        if "vCenter" in version and ("7.0" in version or "8.0" in version):
             log.evidence(f"[L1] {host}: Check if '{version}' is patched against CVE-2024-37079 (DCERPC RCE).")

        # CVE-2021-22005 (vCenter 6.7/7.0 file upload)
        # Often overlaps with 21972 scope.

    def stage_l2_validation(self):
        """L2: Validate permissions (Requires active modification - Skipped)."""
        log.info("[L2] Validation: Active group modification checks skipped for safety.")
