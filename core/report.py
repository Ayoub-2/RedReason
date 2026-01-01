import os
import json
from datetime import datetime

class ReportGenerator:
    def __init__(self, logger_instance):
        self.logs = logger_instance.logs
        self.report_dir = "reports"
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)

    def generate_json(self, target_domain):
        filename = f"{self.report_dir}/RedReason_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        data = {
            "target": target_domain,
            "timestamp": datetime.now().isoformat(),
            "timestamp": datetime.now().isoformat(),
            "risk_score": self.calculate_risk_score(),
            "logs": self.logs
        }
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        return filename

    def generate_markdown(self, target_domain):
        filename = f"{self.report_dir}/RedReason_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"# Red Team Engagement Report: {target_domain}\n")
            f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("## Executive Summary\n")
            f.write("This report details the findings of the automated Red Team engagement. "
                    "The tool focused on validating exploitability rather than just scanning.\n\n")
            
            score = self.calculate_risk_score()
            f.write(f"### Domain Risk Score: {score}/100\n")
            if score > 80: f.write("**Status**: 🚨 CRITICAL RISK DETECTED\n")
            elif score > 50: f.write("**Status**: ⚠️ HIGH RISK\n")
            else: f.write("**Status**: ⚠️ MODERATE RISK\n")
            f.write("\n")
            
            f.write("## Attack Narrative & Reasoning\n")
            f.write("| Type | Description | Status |\n")
            f.write("|---|---|---|\n")
            
            for item in self.logs:
                # Filter for structural logs only
                if item['type'] in ["HYPOTHESIS", "EVIDENCE", "SUCCESS", "FAIL"]:
                    icon = "❓"
                    if item['type'] == "SUCCESS": icon = "✅"
                    elif item['type'] == "FAIL": icon = "❌"
                    elif item['type'] == "EVIDENCE": icon = "🔍"
                    elif item['type'] == "HYPOTHESIS": icon = "🧪"
                    
                    f.write(f"| {icon} {item['type']} | {item['message']} | {item['type']} |\n")

            f.write("\n## Validated Vulnerabilities (PoC)\n")
            successes = [l for l in self.logs if l['type'] == "SUCCESS"]
            if not successes:
                f.write("> No vulnerabilities were confirmed exploitable during this session.\n")
            else:
                for s in successes:
                    f.write(f"### Vulnerability Confirmed\n")
                    f.write(f"**Details**: {s['message']}\n")
                    f.write("Requesting manual review for full exploitation chain.\n\n")

        return filename
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
