# Auto Vuln (RedReason)

An autonomous Red Team operator tool designed for the CRTP mindset.

## Philosophy
- **Reliability > Noise**: Doesn't spray; validates specific vectors.
- **Reasoning**: Logs *why* an attack is attempted (Hypothesis driven).
- **Lab Ready**: Built for Active Directory labs (like alteredsecurity.com).

## Architecture & Extensibility
RedReason is built on a modular architecture designed for "Senior Red Team" operations:
*   **Strict Data Model**: Uses typed objects (`ADUser`, `ADComputer`) for consistency.
*   **State Sharing**: Modules share intelligence to reduce network noise (e.g., Attack module uses Enumeration cache).
*   **Plugin System**: Easily extensible via the `RedReasonModule` interface.

See [Developer Guide](docs/developer_guide.md) for instructions on creating new modules.

## Features
- **Enumeration** (L0-L2 Maturity):
    - Users, Computers, Trusts, LAPS
    - **DNS**: Infrastructure discovery via AD-Integrated zones.
    - **ACLs**: Dangerous ACE detection (GenericAll, WriteDACL).
    - **GPO**: Policy weakness and linkage analysis.
    - **ADCS**: Enterprise CA and ESC1/ESC8 misconfiguration detection.
    - **Lateral**: WinRM/RDP exposure mapping and LAPS coverage.
    - **Defense**: Credential Guard and Defensive Posture checks.

- **Attacks** (L3 Execution):
    - **Kerberoasting**: (Saves hashes to `reports/hashes_kerb.txt`)
    - **AS-REP Roasting**: (Saves hashes to `reports/hashes_asrep.txt`)
    - **Identity Hardening**: Checks for encryption downgrade risks (RC4/DES).
    - **Post-Exploitation**: Golden Ticket forging capabilities.

- **Reasoning Engine**: 
    - Filters False Positives based on prerequisites.
    - Enforces **Maturity Model** (Presence -> Misconfig -> Validation -> Execution).

## MITRE ATT&CK Mapping
RedReason maps its capabilities to the MITRE ATT&CK framework. See full details in [docs/mitre_mapping.md](docs/mitre_mapping.md).

| Attack ID | Technique |
| :--- | :--- |
| **T1558** | Steal or Forge Kerberos Tickets (Kerberoasting, AS-REP) |
| **T1557** | Adversary-in-the-Middle (SMB Relay / Signing) |
| **T1003** | OS Credential Dumping (DCSync) |
| **T1552** | Unsecured Credentials (GPP, LAPS) |
| **T1649** | Steal or Forge Authentication Certificates (AD CS) |

## Installation (Docker)
```bash
docker build -t redreason .
```

## Usage
### Docker (Recommended)
Mount a volume to `/app/reports` to access generated reports and dumped hashes.

```bash
# Standard Scan (All checks)
docker run --rm -v ${PWD}/reports:/app/reports redreason --target <IP> --domain <DOMAIN> --user <USER> --password <PASS> --module all

# Specific Vector Scans
docker run ... --module acl      # Authorization Abuse
docker run ... --module gpo      # Group Policy Abuse
docker run ... --module cs       # ADCS Abuse
docker run ... --module defense  # Defensive Posture

# Pass-the-Hash
docker run --rm -v ${PWD}/reports:/app/reports redreason --target <IP> --domain <DOMAIN> --user <USER> --hashes <LM:NT>
```

### Local Python
```bash
pip install -r requirements.txt
python main.py --target <IP> --domain <DOMAIN> --user <USER> --password <PASS>
```
