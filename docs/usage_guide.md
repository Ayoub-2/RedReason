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

### Debug Mode
If the connection is failing, use `--debug` to see detailed connection logs (LDAP binds, Kerberos errors).

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
