# MITRE ATT&CK Mapping

This document maps the atomic attacks and enumeration techniques performed by **RedReason** to the MITRE ATT&CK framework.

| Attack / Technique | MITRE ID | Description |
| :--- | :--- | :--- |
| **AS-REP Roasting** | [T1558.004](https://attack.mitre.org/techniques/T1558/004/) | Steal or Forge Kerberos Tickets: AS-REP Roasting. Attackers request authentication for users that do not require pre-authentication to obtain a crackable TGT. |
| **Kerberoasting** | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | Steal or Forge Kerberos Tickets: Kerberoasting. Attackers request TGS tickets for services (SPNs) to crack the service account's password offline. |
| **Unconstrained Delegation** | [T1558](https://attack.mitre.org/techniques/T1558/) | Steal or Forge Kerberos Tickets. Abuse of delegation settings to harvest TGTs from incoming connections (e.g., via Printer Bug). |
| **Resource-Based Constrained Delegation (RBCD)** | [T1558](https://attack.mitre.org/techniques/T1558/) | Steal or Forge Kerberos Tickets. Abuse of `msDS-AllowedToActOnBehalfOfOtherIdentity` to impersonate users to a specific computer. |
| **SMB Signing Not Required (NTLM Relay)** | [T1557.001](https://attack.mitre.org/techniques/T1557/001/) | Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay. Lack of SMB signing allows attackers to relay authentication requests to other hosts. |
| **GPP Password Hunting** | [T1552.006](https://attack.mitre.org/techniques/T1552/006/) | Unsecured Credentials: Group Policy Preferences. Recovering passwords stored in SYSVOL XML files using the static AES key. |
| **DCSync Rights (ACL Abuse)** | [T1003.006](https://attack.mitre.org/techniques/T1003/006/) | OS Credential Dumping: DCSync. Abuse of replication rights (`DS-Replication-Get-Changes`) to dump credential data. |
| **LAPS Password Reading** | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | Unsecured Credentials: Credentials In Files. (Or Attribute Access). Reading cleartext passwords (LAPS) stored in the `ms-Mcs-AdmPwd` attribute. |
| **AD CS (Certificate Services)** | [T1649](https://attack.mitre.org/techniques/T1649/) | Steal or Forge Authentication Certificates. Enumerating PKI for vectors like PetitPotam (NTLM Relay to AD CS) or ESC vulnerabilities. |
| **Machine Account Quota** | [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation. Abuse of `ms-DS-MachineAccountQuota` to create machine accounts for use in other attacks (like RBCD). |
| **Enumeration (Users/Groups/Trusts)** | [T1087.002](https://attack.mitre.org/techniques/T1087/002/) | Account Discovery: Domain Account. Enumerating domain users, groups (Domain Admins), and trust relationships ([T1482](https://attack.mitre.org/techniques/T1482/)). |
| **Virtualization Abuse (ESX Admins)** | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | Valid Accounts: Domain Accounts. Abuse of "ESX Admins" group membership (CVE-2024-37085) to gain root access to AD-joined ESXi hosts. |
