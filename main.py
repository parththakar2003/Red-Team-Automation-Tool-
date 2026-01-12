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

from utils.banner import print_banner, print_disclaimer, confirm_authorization, print_colored
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
        '-c', '--config',
        help='Path to custom configuration file'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
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
    
    # Print banner
    print_banner()
    
    # Print disclaimer
    print_disclaimer()
    
    # Confirm authorization
    if not args.skip_auth:
        if not confirm_authorization():
            sys.exit(1)
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
        
        # Initialize orchestrator
        orchestrator = RedTeamOrchestrator()
        
        # Run assessment
        print_colored("\n🚀 Starting Red Team Assessment...\n", "green")
        session = orchestrator.run_assessment(args.target, modules=modules)
        
        # Generate reports
        if not args.no_report:
            print_colored("\n📄 Generating Reports...\n", "cyan")
            
            report_generator = HTMLReportGenerator()
            
            # Generate JSON report
            json_path = report_generator.generate_json(session)
            print_colored(f"✓ JSON Report: {json_path}", "green")
            
            # Generate HTML report unless json-only
            if not args.json_only:
                html_path = report_generator.generate(session)
                print_colored(f"✓ HTML Report: {html_path}", "green")
        
        # Print summary
        print_colored("\n" + "="*75, "cyan")
        print_colored("  Assessment Complete", "green")
        print_colored("="*75, "cyan")
        
        summary = session.get_risk_summary()
        print_colored(f"\nTarget: {session.target.identifier}", "white")
        print_colored(f"Session ID: {session.session_id}", "white")
        print_colored(f"Duration: {session.duration:.2f} seconds", "white")
        print_colored(f"\nFindings Summary:", "yellow")
        print_colored(f"  • Critical: {summary['critical']}", "red")
        print_colored(f"  • High:     {summary['high']}", "yellow")
        print_colored(f"  • Medium:   {summary['medium']}", "blue")
        print_colored(f"  • Low:      {summary['low']}", "green")
        print_colored(f"  • Total:    {summary['critical'] + summary['high'] + summary['medium'] + summary['low']}", "white")
        
        print_colored("\n✓ Assessment completed successfully!\n", "green")
        
        # Exit with appropriate code based on findings
        if summary['critical'] > 0:
            sys.exit(2)  # Critical findings
        elif summary['high'] > 0:
            sys.exit(1)  # High findings
        else:
            sys.exit(0)  # Success
            
    except KeyboardInterrupt:
        print_colored("\n\n⚠️  Assessment interrupted by user", "yellow")
        sys.exit(130)
    except Exception as e:
        print_colored(f"\n❌ Error: {str(e)}", "red")
        logger = Logger.get()
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
