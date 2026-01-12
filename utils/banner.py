"""
Banner and CLI utilities
"""
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)


def print_banner():
    """Print application banner"""
    banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║  {Fore.RED}██████╗ ███████╗██████╗     ████████╗███████╗ █████╗ ███╗   ███╗{Fore.CYAN}  ║
║  {Fore.RED}██╔══██╗██╔════╝██╔══██╗    ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║{Fore.CYAN}  ║
║  {Fore.RED}██████╔╝█████╗  ██║  ██║       ██║   █████╗  ███████║██╔████╔██║{Fore.CYAN}  ║
║  {Fore.RED}██╔══██╗██╔══╝  ██║  ██║       ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║{Fore.CYAN}  ║
║  {Fore.RED}██║  ██║███████╗██████╔╝       ██║   ███████╗██║  ██║██║ ╚═╝ ██║{Fore.CYAN}  ║
║  {Fore.RED}╚═╝  ╚═╝╚══════╝╚═════╝        ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝{Fore.CYAN}  ║
║                                                                       ║
║          {Fore.YELLOW}Red Team Automation Framework v1.0.0{Fore.CYAN}                    ║
║                                                                       ║
║  {Fore.GREEN}Professional Security Assessment Tool{Fore.CYAN}                            ║
║  {Fore.GREEN}For Authorized Testing & Educational Purposes Only{Fore.CYAN}               ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)


def print_disclaimer():
    """Print ethical disclaimer"""
    disclaimer = f"""
{Fore.YELLOW}{'='*75}
                          ⚠️  IMPORTANT DISCLAIMER ⚠️
{'='*75}{Style.RESET_ALL}

{Fore.RED}THIS TOOL IS FOR AUTHORIZED SECURITY TESTING ONLY{Style.RESET_ALL}

{Fore.YELLOW}Legal Requirements:{Style.RESET_ALL}
  • You MUST have explicit written authorization before scanning any system
  • Unauthorized scanning is ILLEGAL and may result in criminal prosecution
  • You are responsible for ensuring compliance with all applicable laws

{Fore.YELLOW}Intended Use:{Style.RESET_ALL}
  • Educational purposes and security research in lab environments
  • Authorized penetration testing with signed agreements
  • Internal security assessments with proper approval
  • Bug bounty programs with defined scope

{Fore.YELLOW}Ethical Guidelines:{Style.RESET_ALL}
  • NO exploitation - proof-of-exposure only
  • NO credential harvesting or data exfiltration
  • NO destructive actions or service disruption
  • RESPECT privacy and handle findings responsibly

{Fore.GREEN}By proceeding, you acknowledge that you have proper authorization and
understand the legal and ethical responsibilities.{Style.RESET_ALL}

{Fore.YELLOW}{'='*75}{Style.RESET_ALL}
"""
    print(disclaimer)


def confirm_authorization() -> bool:
    """
    Prompt user to confirm authorization
    
    Returns:
        True if user confirms, False otherwise
    """
    print(f"\n{Fore.YELLOW}⚠️  Authorization Confirmation Required{Style.RESET_ALL}\n")
    
    response = input(f"{Fore.CYAN}Do you have explicit authorization to scan the target? (yes/no): {Style.RESET_ALL}").strip().lower()
    
    if response not in ['yes', 'y']:
        print(f"\n{Fore.RED}❌ Authorization not confirmed. Exiting.{Style.RESET_ALL}\n")
        return False
    
    response = input(f"{Fore.CYAN}Do you understand this tool is for educational/authorized testing only? (yes/no): {Style.RESET_ALL}").strip().lower()
    
    if response not in ['yes', 'y']:
        print(f"\n{Fore.RED}❌ Acknowledgment not received. Exiting.{Style.RESET_ALL}\n")
        return False
    
    print(f"\n{Fore.GREEN}✓ Authorization confirmed. Proceeding...{Style.RESET_ALL}\n")
    return True


def print_colored(message: str, color: str = 'white'):
    """Print colored message"""
    colors = {
        'red': Fore.RED,
        'green': Fore.GREEN,
        'yellow': Fore.YELLOW,
        'blue': Fore.BLUE,
        'cyan': Fore.CYAN,
        'magenta': Fore.MAGENTA,
        'white': Fore.WHITE
    }
    
    print(f"{colors.get(color, Fore.WHITE)}{message}{Style.RESET_ALL}")


def print_section_header(title: str):
    """Print section header"""
    print(f"\n{Fore.CYAN}{'='*75}")
    print(f"  {title}")
    print(f"{'='*75}{Style.RESET_ALL}\n")
