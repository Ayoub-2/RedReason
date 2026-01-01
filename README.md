# Auto Vuln (RedReason)

An autonomous Red Team operator tool designed for the CRTP mindset.

## Philosophy
- **Reliability > Noise**: Doesn't spray; validates specific vectors.
- **Reasoning**: Logs *why* an attack is attempted (Hypothesis driven).
- **Lab Ready**: Built for Active Directory labs (like alteredsecurity.com).

## Modules
1. **Enumeration**: Maps the domain (DCs, Users, Computers).
2. **Attacks**:
    - Kerberoasting (Saves hashes to `reports/hashes_kerb.txt`)
    - AS-REP Roasting (Saves hashes to `reports/hashes_asrep.txt`)
    - Delegation Abuse Detection (Unconstrained & Constrained)
    - Pass-the-Hash Support
3. **Reasoning Engine**: Filters False Positives based on prerequisites.
4. **Reporting**: Generates Markdown and JSON reports.

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
# Standard Scan
docker run --rm -v ${PWD}/reports:/app/reports redreason --target <IP> --domain <DOMAIN> --user <USER> --password <PASS>

# Pass-the-Hash
docker run --rm -v ${PWD}/reports:/app/reports redreason --target <IP> --domain <DOMAIN> --user <USER> --hashes <LM:NT>
```

### Local Python
```bash
pip install -r requirements.txt
python main.py --target <IP> --domain <DOMAIN> --user <USER> --password <PASS>
```
