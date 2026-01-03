import argparse
import sys
from core.logger import log, ReasoningLogger
from core.report import ReportGenerator
from core.bloodhound import BloodHoundGenerator

from modules import ad_enum, ad_attacks

def main():
    parser = argparse.ArgumentParser(description="RedReason - Autonomous Red Team Operation Tool")
    parser.add_argument("--target", required=True, help="Target Domain or IP")
    parser.add_argument("--user", help="Username for authentication")
    parser.add_argument("--password", help="Password for authentication")
    parser.add_argument("--hashes", help="NTLM hashes (LM:NT)")
    parser.add_argument("--domain", help="Domain Name (if different from target)")
    parser.add_argument("--module", choices=["enum", "attack", "all"], default="all", help="Operation module to run")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument('--bloodhound', action='store_true', help='Generate BloodHound compatible output files')

    args = parser.parse_args()

    # Re-init logger with debug if requested
    if args.debug:
        log.logger.setLevel("DEBUG")

    log.info(f"Starting RedReason against {args.target}")
    log.hypothesis(f"Baseline: Assuming we have network access to {args.target}")

    # Determine target domain for AD operations
    target_domain = args.domain if args.domain else args.target

    try:
        # Orchestration Logic
        if args.module in ["enum", "all"]:
            log.info("Running Enumeration Module...")
            enumerator = ad_enum.ADEnumerator(
                target=args.target,
                domain=target_domain,
                user=args.user,
                password=args.password,
                hashes=args.hashes
            )
            # We need to capture data for BloodHound if requested.
            # This requires ad_enum.run() to return data or we act on the enumerator object.
            # ad_enum.run() just prints currently.
            # We'll need to modify ADEnumerator to store collected users/computers in self.users, etc.
            enumerator.run_all()
            
            if args.bloodhound:
                log.info("Generating BloodHound files...")
                bh = BloodHoundGenerator()
                # Assuming enumerator has populated these lists.
                # We need to ensure ADEnumerator populates these.
                # Since we didn't modify ADEnum to store them explicitly in lists yet, we might miss data.
                # But for this step, we'll assume we can access what we can or pass empty for now 
                # and I will fix ADEnum in next tool call to store this data.
                # Actually, let's fix ADEnum first/concurrently? 
                # I can't do it in this tool call.
                # I will assume enumerator.users and enumerator.computers exist.
                if hasattr(enumerator, 'collected_users'):
                    bh.generate_users(target_domain, enumerator.collected_users)
                if hasattr(enumerator, 'collected_computers'):
                    bh.generate_computers(target_domain, enumerator.collected_computers)
            
        
        if args.module in ["attack", "all"]:
            log.info("Running Attack Module...")
            ad_attacks.run(args)


    except KeyboardInterrupt:
        log.fail("Operation interrupted by user")

    # Generate Report
    reporter = ReportGenerator(log)
    report_file = reporter.generate_markdown(args.target)
    json_file = reporter.generate_json(args.target)
    log.success(f"Reports generated: {report_file}, {json_file}")

if __name__ == "__main__":
    main()
