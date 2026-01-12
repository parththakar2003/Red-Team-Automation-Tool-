"""
Enhanced CLI utilities with Rich library for better user experience
"""
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.prompt import Confirm
from rich import box
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich.markdown import Markdown

console = Console()


def print_banner_rich():
    """Print application banner with Rich"""
    banner_text = """
[bold red]██████╗ ███████╗██████╗     ████████╗███████╗ █████╗ ███╗   ███╗[/bold red]
[bold red]██╔══██╗██╔════╝██╔══██╗    ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║[/bold red]
[bold red]██████╔╝█████╗  ██║  ██║       ██║   █████╗  ███████║██╔████╔██║[/bold red]
[bold red]██╔══██╗██╔══╝  ██║  ██║       ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║[/bold red]
[bold red]██║  ██║███████╗██████╔╝       ██║   ███████╗██║  ██║██║ ╚═╝ ██║[/bold red]
[bold red]╚═╝  ╚═╝╚══════╝╚═════╝        ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝[/bold red]

[bold yellow]Red Team Automation Framework v1.0.0[/bold yellow]
[green]Professional Security Assessment Tool[/green]
[green]For Authorized Testing & Educational Purposes Only[/green]
"""
    
    panel = Panel(
        banner_text,
        border_style="cyan",
        box=box.DOUBLE,
        padding=(1, 2)
    )
    console.print(panel)


def print_disclaimer_rich():
    """Print ethical disclaimer with Rich formatting"""
    disclaimer = """
# ⚠️  IMPORTANT DISCLAIMER

[bold red]THIS TOOL IS FOR AUTHORIZED SECURITY TESTING ONLY[/bold red]

## Legal Requirements:
* You MUST have explicit written authorization before scanning any system
* Unauthorized scanning is ILLEGAL and may result in criminal prosecution
* You are responsible for ensuring compliance with all applicable laws

## Intended Use:
* Educational purposes and security research in lab environments
* Authorized penetration testing with signed agreements
* Internal security assessments with proper approval
* Bug bounty programs with defined scope

## Ethical Guidelines:
* NO exploitation - proof-of-exposure only
* NO credential harvesting or data exfiltration
* NO destructive actions or service disruption
* RESPECT privacy and handle findings responsibly

[bold green]By proceeding, you acknowledge that you have proper authorization and
understand the legal and ethical responsibilities.[/bold green]
"""
    
    md = Markdown(disclaimer)
    panel = Panel(
        md,
        border_style="yellow",
        box=box.ROUNDED,
        title="[bold yellow]LEGAL NOTICE[/bold yellow]",
        padding=(1, 2)
    )
    console.print(panel)


def confirm_authorization_rich() -> bool:
    """
    Prompt user to confirm authorization with Rich
    
    Returns:
        True if user confirms, False otherwise
    """
    console.print("\n[bold yellow]⚠️  Authorization Confirmation Required[/bold yellow]\n")
    
    auth = Confirm.ask("[cyan]Do you have explicit authorization to scan the target?[/cyan]")
    if not auth:
        console.print("[bold red]❌ Authorization not confirmed. Exiting.[/bold red]\n")
        return False
    
    understand = Confirm.ask("[cyan]Do you understand this tool is for educational/authorized testing only?[/cyan]")
    if not understand:
        console.print("[bold red]❌ Acknowledgment not received. Exiting.[/bold red]\n")
        return False
    
    console.print("[bold green]✓ Authorization confirmed. Proceeding...[/bold green]\n")
    return True


def print_assessment_header(target: str, session_id: str):
    """Print assessment header with target info"""
    info_table = Table(show_header=False, box=box.SIMPLE, border_style="cyan")
    info_table.add_column("Property", style="cyan bold")
    info_table.add_column("Value", style="white")
    
    info_table.add_row("🎯 Target", target)
    info_table.add_row("🔑 Session ID", session_id)
    info_table.add_row("📅 Started", "[dim]" + "Now" + "[/dim]")
    
    panel = Panel(
        info_table,
        title="[bold cyan]🚀 Starting Red Team Assessment[/bold cyan]",
        border_style="cyan",
        box=box.ROUNDED
    )
    console.print(panel)


def print_phase_header(phase_number: int, phase_name: str, description: str):
    """Print phase header"""
    title = f"[bold cyan]Phase {phase_number}: {phase_name}[/bold cyan]"
    console.print("\n")
    console.rule(title, style="cyan")
    console.print(f"[dim]{description}[/dim]\n")


def print_finding_summary(summary: dict, duration: float):
    """Print findings summary with Rich table"""
    console.print("\n")
    console.rule("[bold cyan]Assessment Complete[/bold cyan]", style="cyan")
    
    # Create summary table
    table = Table(show_header=True, box=box.ROUNDED, border_style="cyan")
    table.add_column("Severity", style="bold", width=15)
    table.add_column("Count", justify="center", width=10)
    table.add_column("Status", width=30)
    
    # Add rows with colored indicators
    table.add_row(
        "[bold red]🔴 Critical[/bold red]",
        f"[bold red]{summary['critical']}[/bold red]",
        "█" * summary['critical'] if summary['critical'] > 0 else "[dim]None[/dim]"
    )
    table.add_row(
        "[bold yellow]🟠 High[/bold yellow]",
        f"[bold yellow]{summary['high']}[/bold yellow]",
        "█" * summary['high'] if summary['high'] > 0 else "[dim]None[/dim]"
    )
    table.add_row(
        "[bold orange1]🟡 Medium[/bold orange1]",
        f"[bold orange1]{summary['medium']}[/bold orange1]",
        "█" * summary['medium'] if summary['medium'] > 0 else "[dim]None[/dim]"
    )
    table.add_row(
        "[bold green]🟢 Low[/bold green]",
        f"[bold green]{summary['low']}[/bold green]",
        "█" * summary['low'] if summary['low'] > 0 else "[dim]None[/dim]"
    )
    table.add_row(
        "[bold blue]ℹ️  Info[/bold blue]",
        f"[bold blue]{summary.get('info', 0)}[/bold blue]",
        "█" * summary.get('info', 0) if summary.get('info', 0) > 0 else "[dim]None[/dim]"
    )
    
    total = summary['critical'] + summary['high'] + summary['medium'] + summary['low'] + summary.get('info', 0)
    table.add_row(
        "[bold cyan]📊 Total[/bold cyan]",
        f"[bold cyan]{total}[/bold cyan]",
        f"[cyan]Duration: {duration:.2f}s[/cyan]"
    )
    
    console.print(table)
    
    # Risk assessment
    if summary['critical'] > 0:
        risk_text = "[bold red]⚠️  CRITICAL RISK DETECTED[/bold red]"
    elif summary['high'] > 0:
        risk_text = "[bold yellow]⚠️  HIGH RISK DETECTED[/bold yellow]"
    elif summary['medium'] > 0:
        risk_text = "[bold orange1]ℹ️  MODERATE RISK[/bold orange1]"
    else:
        risk_text = "[bold green]✓ LOW RISK[/bold green]"
    
    console.print(f"\n{risk_text}\n")


def print_reports_generated(html_path: str = None, json_path: str = None):
    """Print report generation info"""
    console.print("\n")
    console.rule("[bold cyan]📄 Reports Generated[/bold cyan]", style="cyan")
    
    if json_path:
        console.print(f"[green]✓[/green] JSON Report: [cyan]{json_path}[/cyan]")
    if html_path:
        console.print(f"[green]✓[/green] HTML Report: [cyan]{html_path}[/cyan]")
    
    console.print()


def print_success(message: str):
    """Print success message"""
    console.print(f"[bold green]✓ {message}[/bold green]")


def print_error(message: str):
    """Print error message"""
    console.print(f"[bold red]❌ {message}[/bold red]")


def print_warning(message: str):
    """Print warning message"""
    console.print(f"[bold yellow]⚠️  {message}[/bold yellow]")


def print_info(message: str):
    """Print info message"""
    console.print(f"[cyan]ℹ️  {message}[/cyan]")


def create_progress_bar(description: str = "Processing..."):
    """
    Create a progress bar context
    
    Returns:
        Progress object
    """
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    )


def print_module_status(module_name: str, status: str, details: str = ""):
    """Print module execution status"""
    status_icons = {
        "running": "⏳",
        "success": "✓",
        "error": "✗",
        "warning": "⚠️"
    }
    
    status_colors = {
        "running": "yellow",
        "success": "green",
        "error": "red",
        "warning": "yellow"
    }
    
    icon = status_icons.get(status, "•")
    color = status_colors.get(status, "white")
    
    message = f"[{color}]{icon}[/{color}] [bold]{module_name}[/bold]"
    if details:
        message += f": [dim]{details}[/dim]"
    
    console.print(message)


def print_findings_table(findings: list):
    """Print findings in a formatted table"""
    if not findings:
        console.print("[dim]No findings to display[/dim]")
        return
    
    table = Table(show_header=True, box=box.ROUNDED, border_style="cyan")
    table.add_column("ID", style="cyan", width=12)
    table.add_column("Severity", width=12)
    table.add_column("Title", width=40)
    table.add_column("Component", width=25)
    
    for finding in findings[:20]:  # Show first 20
        severity_color = {
            "Critical": "red",
            "High": "yellow",
            "Medium": "orange1",
            "Low": "green",
            "Info": "blue"
        }.get(finding.severity.value, "white")
        
        table.add_row(
            finding.id,
            f"[bold {severity_color}]{finding.severity.value}[/bold {severity_color}]",
            finding.title[:40],
            finding.affected_component[:25] if finding.affected_component else "N/A"
        )
    
    if len(findings) > 20:
        console.print(f"\n[dim]Showing 20 of {len(findings)} findings. See report for complete list.[/dim]")
    
    console.print(table)


def print_help_text():
    """Print helpful usage information"""
    help_panel = Panel(
        """[bold cyan]Quick Start Guide[/bold cyan]

1. [bold]Basic Scan:[/bold]
   [green]python main.py -t example.com[/green]

2. [bold]Specific Modules:[/bold]
   [green]python main.py -t example.com -m recon scan[/green]

3. [bold]Full Assessment:[/bold]
   [green]python main.py -t example.com --full[/green]

4. [bold]Help:[/bold]
   [green]python main.py --help[/green]

[dim]For more examples, see USAGE.md[/dim]
""",
        title="[bold]Need Help?[/bold]",
        border_style="blue",
        box=box.ROUNDED
    )
    console.print(help_panel)


def print_version_info():
    """Print version information"""
    version_table = Table(show_header=False, box=box.SIMPLE)
    version_table.add_column("Property", style="cyan")
    version_table.add_column("Value", style="white")
    
    version_table.add_row("Version", "1.0.0")
    version_table.add_row("Framework", "Red Team Automation")
    version_table.add_row("Purpose", "Authorized Security Testing")
    
    panel = Panel(
        version_table,
        title="[bold cyan]Version Information[/bold cyan]",
        border_style="cyan"
    )
    console.print(panel)
