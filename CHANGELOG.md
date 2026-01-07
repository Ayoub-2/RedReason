# Changelog

All notable changes to the RedReason project.

## [Unreleased]

### Added
- (Upcoming features go here)

## [1.1.0] - 2026-01-07

### Fixed
- **NameError in `modules/ad_enum.py` (Line 543)**: `sm.save_state(...)` referenced an undefined variable. Fixed by instantiating `SessionManager` in `ADEnumerator.__init__` and using `self.sm.save_state(...)`.
- **IndexError in `core/report.py` (Line 60)**: Unsafe string split operations when parsing "VULNERABLE:" and "CRITICAL:" prefixes caused crashes. Fixed by adding length checks and try-except blocks.
- **KDC_ERR_WRONG_REALM in `modules/ad_attacks.py` (Kerberoasting)**: Kerberoasting now gracefully handles accounts in different realms or forest trusts instead of crashing. Logs debug messages for realm mismatches.
- **Print statement in `main.py` (Exception Handler)**: Replaced `traceback.print_exc()` with `log.trace()` to ensure all output goes through the logging system for consistency and proper formatting.

### Enhanced
- **Stealth Mode (`--stealth` flag)**: 
  - Updated `core/module.py` with `is_stealth_mode()` helper method for all modules to check stealth status.
  - Modified `modules/ad_attacks.py` to skip active coercion checks (PetitPotam, PrintNightmare) in stealth mode.
  - Modified `modules/ad_post.py` to skip RPC enumeration and active session discovery in stealth mode.
  - Added logging to indicate when stealth mode skips operations.
  - Stealth mode flag now properly propagated through `main.py` to all module instances.

- **Verbosity Controls (`-v`/`--verbose` flag)**:
  - Added multi-level verbosity system: `-v` (normal), `-vv` (verbose), `-vvv` (very verbose/trace).
  - Added `set_verbosity()` method to logger for consistent level management.
  - Added `TRACE` level logging for granular diagnostic output.
  - Logger now respects quiet mode (`--verbose 0`) which suppresses non-critical output.
  - Verbosity level is displayed in debug output for transparency.

- **Logging Consistency**: 
  - Audited codebase for print statements and replaced `traceback.print_exc()` with `log.trace()` to ensure all output uses the logging system.

### Added
- Session persistence support via `core/session.py` (session files saved as `session_<target>.json`).
- `log.trace()` method for trace-level diagnostic logging.
- Stealth mode status logging at startup when `--stealth` flag is enabled.

### Changed
- **Removed `--debug` flag**: Consolidated into `-v`, `-vv`, `-vvv` verbosity levels. Use `-vv` for DEBUG level (equivalent to old `--debug`), `-vvv` for TRACE level with exception tracebacks.

## [1.0.0] - 2026-01-07

### Added
- **Production Hardening Phase**:
    - **Global Resilience**: Top-level exception handling in `main.py` for graceful failures.
    - **Code Standardization**: Removal of PoC tags, addition of comprehensive docstrings (e.g., `modules/ad_virt.py`).
    - **Dependency Freeze**: Validated usage of `impacket`, `ldap3`, `pycryptodome` in `requirements.txt`.
    - **Versioning**: Added `VERSION` file tracking release 1.0.0.

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