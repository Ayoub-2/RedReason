# Changelog

All notable changes to the RedReason project.

## [0.1.1] - 2026-01-07

### Added
- **Module: Exchange Operations (`modules/ad_exchange.py`)**:
    - Enumeration of Exchange Servers, Versions, and IPs.
    - Identification of critical groups (`Organization Management`, `Exchange Trusted Subsystem`).
    - Detection of **PrivExchange** vulnerabilities (WriteDACL on Domain).
    - **RBAC Auditing**: Identification of `ApplicationImpersonation` and `Mailbox Import Export` roles.
    - **Hybrid Identity**: Detection of Azure AD Connect (`MSOL_`) accounts.
- **Reporting Enhancements (`core/report.py`)**:
    - implemented **Finding Aggregation** to group similar vulnerabilities (e.g., "50 Roastable Users" -> 1 Finding).
    - Added **Markdown Tables** for Critical Vulnerabilities and Misconfigurations.
    - Introduced **Risk Scoring** and Emoji visual indicators (🔴, 🟠).
    - Added **External References** (HackTricks, MITRE) for remediation.
- **ADCS Improvements (`modules/ad_cs.py`)**:
    - Implemented **Template-to-CA Mapping**: Vulnerable templates (e.g., ESC1) are now verified against published templates on Enterprise CAs.
    - Improved reporting accuracy to distinguish between "vulnerable template exists" (potentially unexploitable) and "vulnerable template is published" (exploitable).
- **Module: Virtualization Operations (`modules/ad_virt.py`)**:
    - **Passive Enum**: Identification of ESXi/vCenter hosts via LDAP (OS & SPN).
    - **Active Fingerprinting**: SOAP probing (`/sdk/vimService`) to extract exact VMware **Build Versions**.
    - **CVE-2024-37085**: Detection of "ESX Admins" abuse (Shadow Admin & Group Hijack).
    - **Vulnerability Correlation**: Mapping fingerprinted versions to critical RCEs (CVE-2021-21972, etc.).

### Fixed
- **Critical Stability Fixes**:
    - **`modules/ad_enum.py`**: Fixed `NameError` by correctly initializing `SessionManager` and ensuring `check_dcsync_rights` is defined.
    - **`core/report.py`**: Fixed `IndexError` during log parsing by making `_aggregate_findings` robust against malformed log messages.
    - **`modules/ad_attacks.py`**: Fixed `AttributeError: 'str' object has no attribute 'decode'` in GPP password decryption checks (Python 3 string handling).
    - **`modules/ad_acl.py`**: Fixed `LDAPControlError` by removing problematic explicit control flags for SD retrieval, falling back to standard effective rights.

### Changed
- **Log Standardization**: Updated `ad_enum.py` and `ad_attacks.py` log messages to follow `VULNERABLE: <Category>: <Details>` format for consistent report aggregation.