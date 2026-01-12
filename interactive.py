#!/usr/bin/env python3
"""
Interactive CLI Mode for Red Team Framework
Provides a menu-driven interface for users who prefer guided interaction
"""

import sys
from pathlib import Path

project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

try:
    from rich.console import Console
    from rich.prompt import Prompt, Confirm
    from rich.panel import Panel
    from rich import box
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False

from core.orchestrator import RedTeamOrchestrator
from reporting.html_generator import HTMLReportGenerator
from core.config import get_config
from core.logger import Logger

if RICH_AVAILABLE:
    from utils.cli_rich import (
        print_banner_rich,
        print_disclaimer_rich,
        print_finding_summary,
        print_reports_generated,
        print_success,
        print_error,
        print_info
    )


def print_menu():
    """Display main menu"""
    if RICH_AVAILABLE:
        menu_text = """
[bold cyan]Main Menu[/bold cyan]

[bold]1.[/bold] Quick Scan (Recon + Scan only)
[bold]2.[/bold] Standard Assessment (Recon + Scan + Enum)
[bold]3.[/bold] Full Security Assessment (All modules)
[bold]4.[/bold] Custom Module Selection
[bold]5.[/bold] Configuration Options
[bold]6.[/bold] View Help & Documentation
[bold]7.[/bold] Exit

[dim]Select an option by entering the number[/dim]
"""
        panel = Panel(menu_text, border_style="cyan", box=box.ROUNDED)
        console.print(panel)
    else:
        print("\n" + "="*60)
        print("Main Menu")
        print("="*60)
        print("1. Quick Scan (Recon + Scan only)")
        print("2. Standard Assessment (Recon + Scan + Enum)")
        print("3. Full Security Assessment (All modules)")
        print("4. Custom Module Selection")
        print("5. Configuration Options")
        print("6. View Help & Documentation")
        print("7. Exit")
        print("="*60)


def get_target():
    """Get target from user"""
    if RICH_AVAILABLE:
        print_info("Enter the target for assessment")
        target = Prompt.ask(
            "[cyan]Target (IP, domain, or CIDR)[/cyan]",
            default="127.0.0.1"
        )
    else:
        print("\nEnter target for assessment:")
        target = input("Target (IP, domain, or CIDR) [127.0.0.1]: ").strip()
        if not target:
            target = "127.0.0.1"
    
    return target


def confirm_scan(target: str, modules: list) -> bool:
    """Confirm scan parameters"""
    if RICH_AVAILABLE:
        info_text = f"""
[bold]Scan Configuration:[/bold]

[cyan]Target:[/cyan] {target}
[cyan]Modules:[/cyan] {', '.join(modules)}

[yellow]⚠️  Ensure you have authorization to scan this target![/yellow]
"""
        panel = Panel(info_text, title="[bold]Confirm Assessment[/bold]", border_style="yellow")
        console.print(panel)
        
        return Confirm.ask("[bold]Proceed with this assessment?[/bold]")
    else:
        print("\n" + "="*60)
        print("Scan Configuration:")
        print(f"Target: {target}")
        print(f"Modules: {', '.join(modules)}")
        print("\n⚠️  Ensure you have authorization to scan this target!")
        print("="*60)
        
        response = input("\nProceed with this assessment? (yes/no): ").strip().lower()
        return response in ['yes', 'y']


def select_custom_modules():
    """Allow user to select custom modules"""
    available_modules = {
        '1': ('recon', 'Reconnaissance'),
        '2': ('scan', 'Port Scanning'),
        '3': ('enum', 'Enumeration'),
        '4': ('vuln', 'Vulnerability Mapping'),
        '5': ('risk', 'Risk Analysis')
    }
    
    if RICH_AVAILABLE:
        print_info("Select modules to run (space-separated numbers):")
        for key, (mod, desc) in available_modules.items():
            console.print(f"  [bold]{key}.[/bold] {desc} ({mod})")
        
        selection = Prompt.ask("[cyan]Modules[/cyan]", default="1 2 3 4 5")
    else:
        print("\nSelect modules to run:")
        for key, (mod, desc) in available_modules.items():
            print(f"  {key}. {desc} ({mod})")
        
        selection = input("Enter numbers (space-separated) [1 2 3 4 5]: ").strip()
        if not selection:
            selection = "1 2 3 4 5"
    
    # Parse selection
    selected = []
    for num in selection.split():
        if num in available_modules:
            selected.append(available_modules[num][0])
    
    return selected if selected else ['recon', 'scan', 'enum', 'vuln', 'risk']


def run_assessment(target: str, modules: list):
    """Run the assessment"""
    try:
        # Initialize
        config = get_config()
        logger = Logger.setup()
        orchestrator = RedTeamOrchestrator()
        
        if RICH_AVAILABLE:
            print_info("Starting assessment...")
        else:
            print("\n🚀 Starting assessment...")
        
        # Run assessment
        session = orchestrator.run_assessment(target, modules=modules)
        
        # Generate reports
        if RICH_AVAILABLE:
            print_info("Generating reports...")
        else:
            print("\n📄 Generating reports...")
        
        report_generator = HTMLReportGenerator()
        json_path = report_generator.generate_json(session)
        html_path = report_generator.generate(session)
        
        # Display results
        summary = session.get_risk_summary()
        
        if RICH_AVAILABLE:
            print_reports_generated(html_path, json_path)
            print_finding_summary(summary, session.duration)
            print_success("Assessment completed successfully!")
        else:
            print(f"\n✓ JSON Report: {json_path}")
            print(f"✓ HTML Report: {html_path}")
            print(f"\nFindings: Critical={summary['critical']}, High={summary['high']}, "
                  f"Medium={summary['medium']}, Low={summary['low']}")
            print("\n✓ Assessment completed successfully!")
        
        return True
        
    except Exception as e:
        if RICH_AVAILABLE:
            print_error(f"Assessment failed: {str(e)}")
        else:
            print(f"\n❌ Error: {str(e)}")
        return False


def show_help():
    """Show help information"""
    if RICH_AVAILABLE:
        help_text = """
[bold cyan]Red Team Framework - Help[/bold cyan]

[bold]Assessment Types:[/bold]

[yellow]Quick Scan:[/yellow] Fast reconnaissance and port scan
[yellow]Standard:[/yellow] Includes web enumeration  
[yellow]Full:[/yellow] Complete security assessment with all modules

[bold]Module Descriptions:[/bold]

[cyan]• Recon:[/cyan] DNS enumeration, subdomain discovery
[cyan]• Scan:[/cyan] Port scanning, service detection
[cyan]• Enum:[/cyan] Web technology identification, directory discovery
[cyan]• Vuln:[/cyan] CVE mapping, misconfiguration detection
[cyan]• Risk:[/cyan] Risk analysis and MITRE ATT&CK mapping

[bold]Important:[/bold]
Always obtain proper authorization before scanning any system!

[bold]For more information:[/bold]
• README.md - Complete documentation
• USAGE.md - Usage examples
• ARCHITECTURE.md - Technical details
"""
        panel = Panel(help_text, border_style="blue", box=box.ROUNDED)
        console.print(panel)
    else:
        print("\n" + "="*60)
        print("Help & Documentation")
        print("="*60)
        print("\nAssessment Types:")
        print("  Quick: Fast recon + port scan")
        print("  Standard: Recon + scan + enumeration")
        print("  Full: Complete assessment with all modules")
        print("\nModule Descriptions:")
        print("  Recon: DNS enumeration, subdomain discovery")
        print("  Scan: Port scanning, service detection")
        print("  Enum: Web technology, directory discovery")
        print("  Vuln: CVE mapping, misconfiguration detection")
        print("  Risk: Risk analysis and MITRE ATT&CK mapping")
        print("\n⚠️  Always obtain authorization before scanning!")
        print("="*60)
    
    input("\nPress Enter to continue...")


def main():
    """Main interactive loop"""
    # Print banner and disclaimer
    if RICH_AVAILABLE:
        print_banner_rich()
        print_disclaimer_rich()
    else:
        print("\n" + "="*60)
        print("Red Team Automation Framework")
        print("Interactive Mode")
        print("="*60)
        print("\n⚠️  FOR AUTHORIZED SECURITY TESTING ONLY")
        print("="*60)
    
    # Authorization check
    if RICH_AVAILABLE:
        if not Confirm.ask("\n[yellow]Do you have authorization to perform security testing?[/yellow]"):
            print_error("Authorization required. Exiting.")
            sys.exit(1)
    else:
        response = input("\nDo you have authorization to perform security testing? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            print("\n❌ Authorization required. Exiting.")
            sys.exit(1)
    
    # Main loop
    while True:
        print_menu()
        
        if RICH_AVAILABLE:
            choice = Prompt.ask("[cyan]Select option[/cyan]", default="1")
        else:
            choice = input("\nSelect option [1]: ").strip()
            if not choice:
                choice = "1"
        
        if choice == '1':
            # Quick scan
            target = get_target()
            modules = ['recon', 'scan']
            if confirm_scan(target, modules):
                run_assessment(target, modules)
        
        elif choice == '2':
            # Standard assessment
            target = get_target()
            modules = ['recon', 'scan', 'enum']
            if confirm_scan(target, modules):
                run_assessment(target, modules)
        
        elif choice == '3':
            # Full assessment
            target = get_target()
            modules = ['recon', 'scan', 'enum', 'vuln', 'risk']
            if confirm_scan(target, modules):
                run_assessment(target, modules)
        
        elif choice == '4':
            # Custom modules
            target = get_target()
            modules = select_custom_modules()
            if confirm_scan(target, modules):
                run_assessment(target, modules)
        
        elif choice == '5':
            # Configuration
            if RICH_AVAILABLE:
                print_info("Configuration editing not yet implemented")
                print_info("Edit config.yaml manually for now")
            else:
                print("\nConfiguration editing not yet implemented.")
                print("Edit config.yaml manually.")
            input("\nPress Enter to continue...")
        
        elif choice == '6':
            # Help
            show_help()
        
        elif choice == '7':
            # Exit
            if RICH_AVAILABLE:
                print_success("Thank you for using Red Team Framework!")
            else:
                print("\n✓ Thank you for using Red Team Framework!")
            break
        
        else:
            if RICH_AVAILABLE:
                print_error("Invalid option. Please select 1-7.")
            else:
                print("\n❌ Invalid option. Please select 1-7.")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        sys.exit(1)
