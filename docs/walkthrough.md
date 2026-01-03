# Walkthrough - Exhaustive Enumeration Upgrade

## Overview
RedReason has been upgraded to provide "exhaustive" enumeration of Active Directory environments. This includes deep dives into users, computers, trusts, and configurations (LAPS, AD CS, GPOs), along with new attack vectors (GPP, SMB Relay checks).

## New Features

### 1. Comprehensive Enumeration (`ad_enum.py`)
- **Detailed User Attributes**: Checks `description` (for passwords), `userAccountControl` (UAC flags), and `badPwdCount`.
- **Domain Trusts**: Maps inbound, outbound, and bidirectional trusts.
- **High-Value Groups**: Enumerates "Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Remote Desktop Users", "Account Operators", "Backup Operators".
- **LAPS**: Checks for readable `ms-Mcs-AdmPwd` attributes on computers (Cleartext Local Admin Passwords).
- **AD CS**: Identifies Certificate Authorities (`pKIEnrollmentService`) for PetitPotam/ESC attacks.
- **GPOs**: Lists all Group Policy Objects.
- **Machine Account Quota**: Checks `ms-DS-MachineAccountQuota` for Shadow Credential/Relay abuse potential.
- **Password Policy**: Retrieves domain password strictness.

### 2. New Attack Vectors (`ad_attacks.py`)
- **GPP Password Hunting**: Scans SYSVOL for XML files (`Groups.xml`, `Services.xml`, etc.) containing `cpassword` attributes and automatically decrypts them using the known static key.
- **SMB Signing Check**: Explicitly checks if SMB Signing is required on the target (Domain Controller). If not, reports vulnerability to NTLM Relaying.

### 3. Advanced Attacks (Phase 2)
- **RBCD (Resource-Based Constrained Delegation)**: Analysis of `msDS-AllowedToActOnBehalfOfOtherIdentity` to find delegation paths.
- **DCSync Rights**: Inspection of the Domain Root ACL for `DS-Replication-Get-Changes` rights to identify potential unauthorized syncers.
- **Service Account Risks**: Correlation of Admin groups with Service Principal Names to find high-risk Kerberoastable accounts.

### 4. Deep Dive & Hygiene (Phase 3)
- **Legacy Protocols**: Detects users/computers allowing only RC4 encryption (weak).
- **AdminSDHolder**: Checks for potential persistence backdoors in the AdminSDHolder ACL.
- **Service Exposure**: Analyzes SPNs to identify hosts exposing RDP, WinRM, MSSQL, or SMB.
- **Service Hygiene**: Flags service accounts with passwords > 1 year old or "Shadow Admin" indicators (adminCount=1).
- **Risk Scoring**: Generates a "Domain Risk Score" (0-100) based on findings to prioritize remediation.

### 5. CAs, Coercion & Visualization (Phase 4)
- **AD CS (Certified Pre-Owned)**:
    - **ESC1**: Enumerates Certificate Templates allowing 'Enrollee Supplies Subject' + 'Client Authentication'.
    - **ESC8**: Identifies AD CS Web Enrollment (HTTP) endpoints vulnerable to NTLM Relay.
- **Coercion**:
    - **PetitPotam**: Checks for exposed `EFSRPC` pipes (MS-EFSR) on DCs.
    - **PrintNightmare**: Checks if the Print Spooler service (`spoolss`) is running on DCs.
- **BloodHound**:
    - Generates `users.json` and `computers.json` compatible with BloodHound 4.x.
    - Usage: `python main.py ... --bloodhound`

## Usage
The usage remains the same. The new checks are automatically integrated into the main workflow.

```bash
# Full Scan (Enumeration + Attacks)
docker run --rm -v ${PWD}/reports:/app/reports redreason --target <IP> --domain <DOMAIN> --user <USER> --password <PASS>
```

## Verification
The code has been updated and syntax checked. 
> [!NOTE]
> Ensure you rebuild the docker image to include the new `pycryptodome` dependency.
> `docker build -t redreason .`
