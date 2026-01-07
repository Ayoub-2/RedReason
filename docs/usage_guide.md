# RedReason Usage Guide: How to Target a Machine

This guide explains how to configure and run **RedReason** to target specific Active Directory environments or machines.

## Prerequisites
- **Target IP**: The IP address of a Domain Controller (preferred) or any domain-joined host.
- **Credentials**: A valid domain user/password OR NTLM hash.
- **Network Access**: The container must be able to reach the target on ports 389 (LDAP), 445 (SMB), and 88 (Kerberos).

---

## 1. Running with Docker (Recommended)

### Standard Scan
This runs all modules (Enumeration + Attacks) against the target.

```bash
docker run --rm -v ${PWD}/reports:/app/reports redreason \
  --target <TARGET_IP> \
  --domain <DOMAIN_NAME> \
  --user <USERNAME> \
  --password <PASSWORD>
```

### Pass-the-Hash (No Password)
If you only have an NTLM hash, use the `--hashes` argument.

```bash
docker run --rm -v ${PWD}/reports:/app/reports redreason \
  --target <TARGET_IP> \
  --domain <DOMAIN_NAME> \
  --user <USERNAME> \
  --hashes <LM:NT>
```
*Note: Format is `LMHASH:NTHASH`. If you only have NT hash, use `00000000000000000000000000000000:NTHASH`.*

---

## 2. Advanced Targeting Options

### Specific Modules
You can limit the operation to just enumeration or just attacks using `--module`.

**Enumeration Only**:
```bash
--module enum
```
*Useful for mapping the network without generating attack traffic.*

**Attacks Only**:
```bash
--module attack
```
*Useful if you already know the lay of the land and just want to check for vulns like Kerberoasting.*

### Advanced Modules (Phase 7 Vectors)
RedReason supports granular targeting.

**Authorized Abuse (ACLs)**:
```bash
--module acl
```
*Identifies Dangerous ACEs (GenericAll, WriteDACL, etc).*

**Group Policy Abuse (GPO)**:
```bash
--module gpo
```
*Checks for weak GPO permissions and risky linkages.*

**ADCS Abuse**:
```bash
--module cs
```
*Scans for Vulnerable Templates (ESC1) and Enterprise CAs.*

**Lateral Movement Exposure**:
```bash
--module lateral
```
*Passive checks for LAPS, SPN exposure (WinRM/RDP).*

**Defensive Posture**:
```bash
--module defense
```
*Checks for Credential Guard and other hardening controls.*

### Post-Exploitation
```bash
--module post
```

### Exchange Operations
```bash
--module exchange
```
*Enumerates Exchange infrastructure, validates PrivExchange, and audits RBAC permissions.*

### Virtualization Operations
```bash
--module virt
```
*Enumerates ESXi/vCenter hosts, fingerprints versions (SOAP), and checks for CVE-2024-37085 ("ESX Admins" abuse).*

*Run this AFTER enumeration to find active sessions (User Hunter) or forge tickets.*

### Debug Mode
If the connection is failing, use `--debug` to see detailed connection logs.

```bash
--debug
```

---

## 3. Interpreting Results

Artifacts are saved to the mapped `reports/` folder:
1.  **Markdown Report (`.md`)**: High-level summary, Risk Score, and narrative. Read this first.
2.  **JSON Report (`.json`)**: Raw data for programmatic ingestion.
3.  **Hash Files (`.txt`)**:
    -   `hashes_kerb.txt`: Kerberoasting hashes (crack with hashcat mode 13100).
    -   `hashes_asrep.txt`: AS-REP hashes (crack with hashcat mode 18200).
    -   `gpp_passwords.txt`: Decrypted Group Policy Preferences passwords.

## Troubleshooting
- **"LDAP Connection Failed"**: Ensure you are targeting the Domain Controller. Check firewall rules for port 389.
- **"Kerberos Error"**: Ensure the Time Synchronization between your host and the target DC is within 5 minutes.
