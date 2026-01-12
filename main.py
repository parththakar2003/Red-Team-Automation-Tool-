#!/usr/bin/env python3
"""
Red Team Automation Framework - Main CLI Entry Point

A professional Red Team assessment tool for authorized security testing.
Follows the Red Team Kill Chain methodology:
  Reconnaissance → Scanning → Enumeration → Vulnerability Mapping → Risk Analysis → Reporting

Author: Security Assessment Team
Version: 1.0.0
License: For Educational and Authorized Testing Only
"""

import sys
import argparse
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Try to import Rich CLI utilities, fallback to basic if not available
try:
    from utils.cli_rich import (
        print_banner_rich as print_banner,
        print_disclaimer_rich as print_disclaimer,
        confirm_authorization_rich as confirm_authorization,
        print_assessment_header,
        print_phase_header,
        print_finding_summary,
        print_reports_generated,
        print_success,
        print_error,
        print_warning,
        print_info,
        print_module_status,
        print_findings_table,
        console
    )
    RICH_AVAILABLE = True
except ImportError:
    from utils.banner import print_banner, print_disclaimer, confirm_authorization, print_colored
    RICH_AVAILABLE = False

from core.orchestrator import RedTeamOrchestrator
from reporting.html_generator import HTMLReportGenerator
from core.config import get_config
from core.logger import Logger


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Red Team Automation Framework - Professional Security Assessment Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a single IP address
  python main.py -t 192.168.1.100
  
  # Scan a domain
  python main.py -t example.com
  
  # Scan with specific modules
  python main.py -t example.com -m recon scan enum
  
  # Full assessment with all modules
  python main.py -t example.com --full
  
  # Skip authorization prompt (use only if authorized!)
  python main.py -t example.com --skip-auth
  
  # Quiet mode with minimal output
  python main.py -t example.com --quiet

Important: This tool is for authorized security testing only!
        """
    )
    
    parser.add_argument(
        '-t', '--target',
        required=True,
        help='Target to assess (IP address, domain, or CIDR range)'
    )
    
    parser.add_argument(
        '-m', '--modules',
        nargs='+',
        choices=['recon', 'scan', 'enum', 'vuln', 'risk'],
        help='Modules to run (default: all modules)'
    )
    
    parser.add_argument(
        '--full',
        action='store_true',
        help='Run full assessment with all modules'
    )
    
    parser.add_argument(
        '--skip-auth',
        action='store_true',
        help='Skip authorization confirmation (use only if authorized!)'
    )
    
    parser.add_argument(
        '--no-report',
        action='store_true',
        help='Skip report generation'
    )
    
    parser.add_argument(
        '--json-only',
        action='store_true',
        help='Generate JSON report only (no HTML)'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output directory for reports (default: reports/)'
    )
    
    parser.add_argument(
        '-c', '--config',
        help='Path to custom configuration file'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Quiet mode - minimal output'
    )
    
    parser.add_argument(
        '--show-findings',
        action='store_true',
        help='Display findings table in console'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Red Team Automation Framework v1.0.0'
    )
    
    return parser.parse_args()


def main():
    """Main entry point"""
    # Parse arguments
    args = parse_arguments()
    
    # Print banner (unless quiet mode)
    if not args.quiet:
        print_banner()
        print_disclaimer()
    
    # Confirm authorization
    if not args.skip_auth:
        if not confirm_authorization():
            sys.exit(1)
    else:
        if RICH_AVAILABLE:
            print_warning("Authorization check skipped - ensure you have proper authorization!")
        else:
            print_colored("⚠️  Authorization check skipped - ensure you have proper authorization!", "yellow")
    
    try:
        # Initialize configuration
        if args.config:
            config = get_config(args.config)
        else:
            config = get_config()
        
        # Setup logger
        logger = Logger.setup()
        
        # Determine modules to run
        modules = args.modules if args.modules else None
        if args.full:
            modules = ['recon', 'scan', 'enum', 'vuln', 'risk']
        
        # Print assessment header
        if not args.quiet and RICH_AVAILABLE:
            print_assessment_header(args.target, "Starting...")
        
        # Initialize orchestrator
        orchestrator = RedTeamOrchestrator()
        
        # Run assessment with enhanced CLI feedback
        if not args.quiet and RICH_AVAILABLE:
            print_info("Starting Red Team Assessment...")
        
        session = orchestrator.run_assessment(args.target, modules=modules)
        
        # Generate reports
        if not args.no_report:
            if not args.quiet:
                if RICH_AVAILABLE:
                    print_info("Generating Reports...")
                else:
                    print_colored("\n📄 Generating Reports...\n", "cyan")
            
            report_generator = HTMLReportGenerator()
            
            # Generate JSON report
            json_path = report_generator.generate_json(session)
            
            # Generate HTML report unless json-only
            html_path = None
            if not args.json_only:
                html_path = report_generator.generate(session)
            
            if not args.quiet:
                if RICH_AVAILABLE:
                    print_reports_generated(html_path, json_path)
                else:
                    print_colored(f"✓ JSON Report: {json_path}", "green")
                    if html_path:
                        print_colored(f"✓ HTML Report: {html_path}", "green")
        
        # Print summary
        summary = session.get_risk_summary()
        
        if not args.quiet:
            if RICH_AVAILABLE:
                print_finding_summary(summary, session.duration)
                
                # Show findings table if requested
                if args.show_findings and session.findings:
                    console.print("\n")
                    console.rule("[bold cyan]Top Findings[/bold cyan]", style="cyan")
                    print_findings_table(session.findings)
                
            else:
                print_colored("\n" + "="*75, "cyan")
                print_colored("  Assessment Complete", "green")
                print_colored("="*75, "cyan")
                
                print_colored(f"\nTarget: {session.target.identifier}", "white")
                print_colored(f"Session ID: {session.session_id}", "white")
                print_colored(f"Duration: {session.duration:.2f} seconds", "white")
                print_colored(f"\nFindings Summary:", "yellow")
                print_colored(f"  • Critical: {summary['critical']}", "red")
                print_colored(f"  • High:     {summary['high']}", "yellow")
                print_colored(f"  • Medium:   {summary['medium']}", "blue")
                print_colored(f"  • Low:      {summary['low']}", "green")
                print_colored(f"  • Total:    {summary['critical'] + summary['high'] + summary['medium'] + summary['low']}", "white")
        
        if not args.quiet:
            if RICH_AVAILABLE:
                print_success("Assessment completed successfully!")
            else:
                print_colored("\n✓ Assessment completed successfully!\n", "green")
        
        # Exit with appropriate code based on findings
        if summary['critical'] > 0:
            sys.exit(2)  # Critical findings
        elif summary['high'] > 0:
            sys.exit(1)  # High findings
        else:
            sys.exit(0)  # Success
            
    except KeyboardInterrupt:
        if RICH_AVAILABLE:
            print_warning("\n\nAssessment interrupted by user")
        else:
            print_colored("\n\n⚠️  Assessment interrupted by user", "yellow")
        sys.exit(130)
    except Exception as e:
        if RICH_AVAILABLE:
            print_error(f"Error: {str(e)}")
        else:
            print_colored(f"\n❌ Error: {str(e)}", "red")
        logger = Logger.get()
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
