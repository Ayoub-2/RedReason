import os
import json
from datetime import datetime

class ReportGenerator:
    def __init__(self, logger_instance):
        self.logs = logger_instance.logs
        self.report_dir = "reports"
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)

        # Knowledge Base for References
        self.kb = {
            "AS-REP Roasting": "https://hacktricks.xyz/windows-hardening/active-directory-methodology/asrep-roasting",
            "Kerberoasting": "https://hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoasting",
            "DCSync": "https://hacktricks.xyz/windows-hardening/active-directory-methodology/dcsync",
            "Unconstrained Delegation": "https://hacktricks.xyz/windows-hardening/active-directory-methodology/delegation#unconstrained-delegation",
            "Constrained Delegation": "https://hacktricks.xyz/windows-hardening/active-directory-methodology/delegation#constrained-delegation",
            "RBCD": "https://hacktricks.xyz/windows-hardening/active-directory-methodology/delegation#resource-based-constrained-delegation",
            "GPP": "https://adsecurity.org/?p=2288",
            "SMB Signing": "https://hacktricks.xyz/windows-hardening/active-directory-methodology/smb-signing",
            "Zerologon": "https://www.secura.com/blog/zerologon",
            "PetitPotam": "https://github.com/topotam/PetitPotam",
            "ESC1": "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
            "LAPS": "https://adsecurity.org/?p=1790"
        }

    def generate_json(self, target_domain):
        filename = f"{self.report_dir}/RedReason_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        data = {
            "target": target_domain,
            "timestamp": datetime.now().isoformat(),
            "risk_score": self.calculate_risk_score(),
            "summary": self._aggregate_findings(),
            "raw_logs": self.logs
        }
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        return filename

    def _aggregate_findings(self):
        """Helper to aggregate logs into findings."""
        findings = {
            "critical": {},
            "misconfig": {}
        }
        
        for item in self.logs:
            msg = item['message']
            type_ = item['type']
            
            # Simple Heuristic for Categorization
            if type_ == "SUCCESS" or "VULNERABLE" in msg or "CRITICAL" in msg:
                category = "critical"
                # Extract clean title (Split by ':' or take first 5 words)
                if ":" in msg:
                    title = msg.split(":")[1].strip() # Take part after "VULNERABLE: <Title>" or "CRITICAL: <Title>"
                    # If the message starts directly with text, try to find the distinctive part
                    if "VULNERABLE" in msg:
                         title = msg.split("VULNERABLE:")[1].split(":")[0].strip() if ":" in msg.split("VULNERABLE:")[1] else msg.split("VULNERABLE:")[1].strip()
                    elif "CRITICAL" in msg:
                         title = msg.split("CRITICAL:")[1].strip()
                else:
                    title = msg # Fallback
            
            elif type_ == "EVIDENCE" or "Exposure" in msg or "Weak" in msg:
                category = "misconfig"
                title = msg.split(":")[0].strip() if ":" in msg else msg
            
            else:
                continue

            # normalize title slightly for aggregation
            # Remove specific usernames/machines if they are at the end
            # This is a basic normalization for PoC. 
            # Ideally we'd use a finding ID in the logger.
            
            # Grouping
            if title not in findings[category]:
                findings[category][title] = []
            findings[category][title].append(msg)
            
        return findings

    def generate_markdown(self, target_domain):
        filename = f"{self.report_dir}/RedReason_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        
        aggregated = self._aggregate_findings()
        score = self.calculate_risk_score()
        
        with open(filename, "w", encoding="utf-8") as f:
            # Header
            f.write(f"# 🛡️ Red Team Engagement Report: {target_domain}\n")
            f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Executive Summary
            f.write("## 1. Executive Summary\n")
            f.write(f"**Domain Risk Score**: `{score}/100`\n\n")
            
            if score > 80:
                f.write("> [!CAUTION]\n> 🚨 **CRITICAL RISK DETECTED**: Immediate remediation is required. Domain compromise is highly likely or already demonstrated.\n\n")
            elif score > 50:
                f.write("> [!WARNING]\n> ⚠️ **HIGH RISK**: Multiple high-severity misconfigurations identified. Lateral movement paths exist.\n\n")
            else:
                f.write("> [!NOTE]\n> ⚠️ **MODERATE RISK**: Standard misconfigurations found. Review hardening guidelines.\n\n")

            # Critical Vulnerabilities Table
            f.write("## 2. 💀 Critical Vulnerabilities\n")
            if aggregated['critical']:
                f.write("| Vulnerability | Assets Affected | Risk | References |\n")
                f.write("|---|---|---|---|\n")
                for title, instances in aggregated['critical'].items():
                    count = len(instances)
                    ref_link = self._get_ref_link(title)
                    f.write(f"| **{title}** | {count} | 🔴 Critical | {ref_link} |\n")
            else:
                f.write("✅ No critical exploit paths confirmed.\n")
            f.write("\n")

            # Misconfigurations Table
            f.write("## 3. ⚠️ Misconfigurations & Exposures\n")
            if aggregated['misconfig']:
                f.write("| Issue | Occurrences | Risk | Impact |\n")
                f.write("|---|---|---|---|\n")
                for title, instances in aggregated['misconfig'].items():
                    count = len(instances)
                    f.write(f"| {title} | {count} | 🟠 Medium | Expanded Attack Surface |\n")
            else:
                f.write("✅ No significant misconfigurations found.\n")
            f.write("\n")

            # Detailed Analysis
            f.write("## 4. 🔍 Detailed Analysis & Evidence\n")
            f.write("Specific objects and proof of concepts for the findings above.\n\n")
            
            for category, data in aggregated.items():
                if not data: continue
                icon = "💀" if category == "critical" else "⚠️"
                
                for title, instances in data.items():
                    f.write(f"### {icon} {title}\n")
                    f.write(f"**Impact**: Allows attackers to escalate privileges or move laterally.\n")
                    f.write(f"**Reference**: {self._get_ref_link(title, raw=True)}\n\n")
                    f.write("**Affected Assets**:\n")
                    
                    if len(instances) > 10:
                        f.write(f"> **{len(instances)} assets affected.** (Showing first 10)\n")
                        for msg in instances[:10]:
                            f.write(f"- `{msg}`\n")
                        f.write(f"- *(...and {len(instances)-10} more. See JSON report)*\n")
                    else:
                        for msg in instances:
                            f.write(f"- `{msg}`\n")
                    f.write("\n")

        return filename

    def _get_ref_link(self, title, raw=False):
        """Match title against KB."""
        for key, url in self.kb.items():
            if key.lower() in title.lower():
                return url if raw else f"[{key}]({url})"
        return "N/A"

    def calculate_risk_score(self):
        # Basic scoring algorithm
        score = 0
        for item in self.logs:
            if item['type'] == "SUCCESS": # Confirmed Vuln / Critical
                score += 10
            elif item['type'] == "FAIL" and "VULNERABLE" in item['message']: # Found but failed exploit
                 score += 8
            elif "VULNERABLE" in item['message'] or "CRITICAL" in item['message']: # Textual match
                 score += 8
            elif item['type'] == "EVIDENCE": # Finding
                score += 1
        
        return min(score, 100) # Cap at 100
