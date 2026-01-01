import argparse
import sys
from core.logger import log, ReasoningLogger
from core.report import ReportGenerator

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

    args = parser.parse_args()

    # Re-init logger with debug if requested
    if args.debug:
        log.logger.setLevel("DEBUG")

    log.info(f"Starting RedReason against {args.target}")
    log.hypothesis(f"Baseline: Assuming we have network access to {args.target}")

    try:
        # Orchestration Logic
        if args.module in ["enum", "all"]:
            log.info("Running Enumeration Module...")
            ad_enum.run(args)


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
