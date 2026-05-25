# RedReason v1.1.0 🛡️

![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen) ![Version](https://img.shields.io/badge/Version-1.1.0-blue)

An autonomous Red Team operator tool designed for the CRTP mindset.

## Philosophy
- **Reliability > Noise**: Doesn't spray; validates specific vectors.
- **Reasoning**: Logs *why* an attack is attempted (Hypothesis driven).
- **Lab Ready**: Built for Active Directory labs (like alteredsecurity.com).

## Architecture & Extensibility
RedReason is built on a robust, standardized modular architecture designed for enterprise-grade security engagements:
*   **MaturityFlowEngine Lifecycle**: Enforces structured execution boundaries (`stage_l0_presence` through `stage_l3_execution`) to ensure safe validation ceilings (e.g. passive mode ceilings).
*   **Relational SQLite Graph Cache**: Saves domain state in an ACID-compliant SQLite transactional database, representing graph relationships between users, computers, group memberships, trusts, and GPOs. This facilitates internal graph traversal and complex relationship query paths.
*   **Plugin System**: Easily extensible by subclassing the unified `RedReasonModule` base contract.

See [Developer Guide](docs/developer_guide.md) for instructions on creating new modules.

## Security & Architecture Analysis
For a deep dive into the security posture, threat model, pentester-level review, and core upgrades of RedReason, see [Executive Security & Architecture Analysis Report](project-docs/analysis/project_analysis_and_propositions.md).



## Features
- **Enumeration** (L0-L2 Maturity):
    - Users, Computers, Trusts, LAPS
    - **DNS**: Infrastructure discovery via AD-Integrated zones.
    - **ACLs**: Dangerous ACE detection (GenericAll, WriteDACL).
    - **GPO**: Policy weakness and linkage analysis.
    - **ADCS**: Enterprise CA and ESC1/ESC8 misconfiguration detection.
    - **Exchange**: Server enumeration, PrivExchange (ACLs), and RBAC auditing.
    - **Virtualization**: ESXi/vCenter enumeration, "ESX Admins" abuse (CVE-2024-37085), and Version Fingerprinting.
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
docker run ... --module exchange # Exchange Ops
docker run ... --module virt     # Virtualization Ops
docker run ... --module defense  # Defensive Posture

# Pass-the-Hash
docker run --rm -v ${PWD}/reports:/app/reports redreason --target <IP> --domain <DOMAIN> --user <USER> --hashes <LM:NT>
```

### Local Python
```bash
pip install -r requirements.txt
python main.py --target <IP> --domain <DOMAIN> --user <USER> --password <PASS>
```

## Command-Line Options (v1.1.0+)

### Verbosity Control
Control output detail level with multi-level verbosity:
```bash
# Quiet mode (warnings only)
python main.py --target <IP> ... --verbose 0

# Normal mode (default, INFO level)
python main.py --target <IP> ...

# Verbose mode (DEBUG level, detailed checks)
python main.py --target <IP> ... -v

# Very verbose mode (TRACE level, granular diagnostics)
python main.py --target <IP> ... -vvv
```

### Stealth Mode
Passive-only scanning to avoid triggering detection systems:
```bash
# Enable stealth mode (skips active coercion attacks, RPC enumeration)
python main.py --target <IP> ... --stealth
```

### Additional Flags
```bash
--bloodhound         # Generate BloodHound JSON output
--module <name>      # Run specific module (enum, attack, post, acl, gpo, cs, lateral, defense, exchange, virt, all)
--hashes <LM:NT>     # Use pass-the-hash authentication
```

## License
This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

**Copyright (c) 2026 RedReason Authors**

You are free to use, modify, and distribute this software under the terms of the MIT License. This tool is provided "as is" without any warranty.

## Disclaimer
RedReason is designed for authorized security testing and red team operations in controlled environments (e.g., lab environments, authorized penetration tests). Unauthorized access to computer systems is illegal. Always obtain proper authorization before conducting security assessments.