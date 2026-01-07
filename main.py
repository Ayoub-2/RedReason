import argparse
import sys
from core.logger import log, ReasoningLogger
from core.report import ReportGenerator
from core.bloodhound import BloodHoundGenerator

from modules import ad_enum, ad_attacks, ad_post, ad_acl, ad_gpo, ad_cs, ad_lateral, ad_defense, ad_exchange

def main():
    parser = argparse.ArgumentParser(description="RedReason - Autonomous Red Team Operation Tool")
    parser.add_argument("--target", required=True, help="Target Domain or IP")
    parser.add_argument("--user", help="Username for authentication")
    parser.add_argument("--password", help="Password for authentication")
    parser.add_argument("--hashes", help="NTLM hashes (LM:NT)")
    parser.add_argument("--domain", help="Domain Name (if different from target)")
    parser.add_argument("--module", choices=["enum", "attack", "post", "acl", "gpo", "cs", "lateral", "defense", "exchange", "virt", "all"], default="all", help="Operation module to run")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity (-v, -vv, -vvv)")
    parser.add_argument('--bloodhound', action='store_true', help='Generate BloodHound compatible output files')
    parser.add_argument('--stealth', action='store_true', help='Enable Stealth Mode (Passive Checks Only)')

    args = parser.parse_args()

    # Re-init logger with appropriate level
    # Verbosity: 0=WARNING, 1=INFO (default), 2=DEBUG, 3+=TRACE (very verbose)
    if args.debug or args.verbose >= 2:
        log.logger.setLevel("DEBUG")
    if args.verbose == 0:
        log.logger.setLevel("WARNING")
    
    # Set verbosity level in logger for internal tracking
    log.set_verbosity(args.verbose if not args.debug else max(args.verbose, 2))
    
    log.info(f"Starting RedReason against {args.target}")
    
    # Display settings
    if args.stealth:
        log.info("🥷 STEALTH MODE ENABLED: Passive checks only (no active exploitation)")
    if args.verbose > 0:
        log.debug(f"Verbosity Level: {args.verbose} (0=quiet, 1=normal, 2=verbose, 3+=very verbose)")
    if args.bloodhound:
        log.debug("BloodHound output will be generated")
    
    log.hypothesis(f"Baseline: Assuming we have network access to {args.target}")

    # Determine target domain for AD operations
    target_domain = args.domain if args.domain else args.target

    try:
        # Orchestration Logic
        # Orchestration Logic
        # Try to load session first to populate context if we skipped enum
        from core.session import SessionManager
        sm = SessionManager(args.target)
        cached_users, cached_computers = sm.load_state()

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
            if not enumerator.run_all():
                log.fail("Critical Failure: Initial LDAP connection failed. Aborting operations.")
                sys.exit(1)
            
            if args.bloodhound:
                log.info("Generating BloodHound files...")
                bh = BloodHoundGenerator()

                if hasattr(enumerator, 'collected_users'):
                    bh.generate_users(target_domain, enumerator.collected_users)
                if hasattr(enumerator, 'collected_computers'):
                    bh.generate_computers(target_domain, enumerator.collected_computers)
            
        
        if args.module in ["attack", "all"]:
            log.info("Running Attack Module...")
            # state sharing
            # If we didn't run enumeration just now, but we loaded a session, create a dummy enumerator to hold state
            if 'enumerator' not in locals():
                 # Create a shell enumerator just to hold the data
                 enumerator = ad_enum.ADEnumerator(args.target, target_domain, args.user, args.password, args.hashes)
                 if cached_users: enumerator.collected_users = cached_users
                 if cached_computers: enumerator.collected_computers = cached_computers

            current_state = enumerator if 'enumerator' in locals() else None
            
            attacker = ad_attacks.ADAttacker(
                target=args.target, 
                domain=target_domain, 
                user=args.user, 
                password=args.password, 
                hashes=args.hashes,
                enumeration_data=current_state
            )
            attacker.run(args)


        if args.module in ["post", "all"]:
            log.info("Running Post-Exploitation Module...")
            # state sharing
            current_state = enumerator if 'enumerator' in locals() else None
            
            post_ex = ad_post.ADPostExploitation(
                target=args.target,
                domain=target_domain,
                user=args.user,
                password=args.password,
                hashes=args.hashes,
                enumeration_data=current_state
            )
            post_ex.run(args)


        if args.module in ["acl", "all"]:
            log.info("Running ACL & Authorization Module...")
            # state sharing
            current_state = enumerator if 'enumerator' in locals() else None
            
            acl_mod = ad_acl.ADACLAbuse(
                target=args.target,
                domain=target_domain,
                user=args.user,
                password=args.password,
                hashes=args.hashes,
                enumeration_data=current_state
            )
            acl_mod.run(args)


        if args.module in ["gpo", "all"]:
            log.info("Running GPO Abuse Module...")
            # state sharing
            current_state = enumerator if 'enumerator' in locals() else None
            
            gpo_mod = ad_gpo.ADGPOAbuse(
                target=args.target,
                domain=target_domain,
                user=args.user,
                password=args.password,
                hashes=args.hashes,
                enumeration_data=current_state
            )
            gpo_mod.run(args)


        if args.module in ["cs", "all"]:
            log.info("Running ADCS Abuse Module...")
            # state sharing
            current_state = enumerator if 'enumerator' in locals() else None
            
            cs_mod = ad_cs.ADCSAbuse(
                target=args.target,
                domain=target_domain,
                user=args.user,
                password=args.password,
                hashes=args.hashes,
                enumeration_data=current_state
            )
            cs_mod.run(args)


        if args.module in ["lateral", "all"]:
            log.info("Running Lateral Movement Exposure Module...")
            # state sharing
            current_state = enumerator if 'enumerator' in locals() else None
            
            lat_mod = ad_lateral.ADLateralMovement(
                target=args.target,
                domain=target_domain,
                user=args.user,
                password=args.password,
                hashes=args.hashes,
                enumeration_data=current_state
            )
            lat_mod.run(args)


        if args.module in ["defense", "all"]:
            log.info("Running Defensive Posture Module...")
            # state sharing
            current_state = enumerator if 'enumerator' in locals() else None
            
            def_mod = ad_defense.ADDefenseAwareness(
                target=args.target,
                domain=target_domain,
                user=args.user,
                password=args.password,
                hashes=args.hashes,
                enumeration_data=current_state
            )
            def_mod.run(args)


        if args.module in ["exchange", "all"]:
            log.info("Running Exchange Operations Module...")
            # state sharing
            current_state = enumerator if 'enumerator' in locals() else None
            
            exch_mod = ad_exchange.ADExchangeOps(
                target=args.target,
                domain=target_domain,
                user=args.user,
                password=args.password,
                hashes=args.hashes,
                enumeration_data=current_state
            )
            exch_mod.run(args)


        if args.module in ["virt", "all"]:
            log.info("Running Virtualization Operations Module...")
            # state sharing
            current_state = enumerator if 'enumerator' in locals() else None
            
            # Import here to avoid circular imports if needed, though top-level is fine
            from modules.ad_virt import ADVirtualizationOps 
            
            virt_mod = ADVirtualizationOps(
                target=args.target,
                domain=target_domain,
                user=args.user,
                password=args.password,
                hashes=args.hashes,
                enumeration_data=current_state
            )
            virt_mod.run(args)


    except KeyboardInterrupt:
        log.fail("Operation interrupted by user")
    except Exception as e:
        log.fail(f"Unhandled Exception: {str(e)}")
        if args.debug:
            import traceback
            tb_str = traceback.format_exc()
            log.trace(f"Exception Traceback:\n{tb_str}")

    # Generate Report
    reporter = ReportGenerator(log)
    report_file = reporter.generate_markdown(args.target)
    json_file = reporter.generate_json(args.target)
    log.success(f"Reports generated: {report_file}, {json_file}")

if __name__ == "__main__":
    main()
