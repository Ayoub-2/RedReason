# RedReason - Project Analysis

## Overview
RedReason is an autonomous Red Team operator tool designed for Active Directory environments. It focuses on reliability and reasoning, logging *why* an attack is attempted rather than just spraying attacks. It supports enumeration, specific attacks (Kerberoasting, AS-REP Roasting, Delegation Abuse), and detailed reporting.

## Project Structure
- **Root Directory**: Contains configuration files (`Dockerfile`, `requirements.txt`) and variable entry point (`main.py`).
- **core/**: Core infrastructure.
    - `logger.py`: Custom logger supporting "Reasoning" log types (Hypothesis, Evidence, etc.).
    - `report.py`: Generates Markdown and JSON reports.
- **modules/**: Operational modules.
    - `ad_enum.py`: Handles LDAP enumeration (finding Domain Controllers).
    - `ad_attacks.py`: Implements attack logic using `impacket` and `ldap3`.

## Key Capabilities
1.  **Enumeration**:
    - Connects to LDAP (supports Pass-the-Hash).
    - Identifies Domain Controllers.
2.  **Attacks**:
    - **AS-REP Roasting**: Identifies accounts with `DONT_REQ_PREAUTH` and dumps TGTs.
    - **Kerberoasting**: Identifies accounts with SPNs and dumps TGSs.
    - **Delegation Abuse**: Checks for Unconstrained and Constrained Delegation configurations.
3.  **Reporting**:
    - Outputs structured reports (Markdown/JSON) to `reports/` directory.

## Code Quality & Architecture
- **Dependency Management**: Uses `impacket` for Kerberos interactions and `ldap3` for directory queries.
- **Modularity**: Logic is separated into modules, making it extensible.
- **Docker Support**: Includes a `Dockerfile` for easy deployment and usage, ensuring consistent dependencies (especially system-level ones like `gcc` and `krb5`).
- **Logging**: The "Reasoning Engine" approach in logging is a strong feature, making the tool's actions transparent and educational.

## Observations
- The tool seems "Lab Ready" and focused on validation rather than large-scale scanning.
- It handles credentials effectively, supporting both password and NTLM hash authentication.
- The `Dockerfile` is well-constructed, including necessary build tools for crypto libraries.
