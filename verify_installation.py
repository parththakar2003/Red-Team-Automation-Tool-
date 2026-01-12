#!/usr/bin/env python3
"""
Installation Verification Script for Red Team Automation Framework

This script verifies that all required dependencies and tools are properly installed
and configured for the Red Team Automation Framework.

Usage:
    python verify_installation.py
    # Or from activated virtual environment:
    python3 verify_installation.py
"""

import sys
import subprocess
import importlib.util
from pathlib import Path


class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def print_status(message, status='info'):
    """Print formatted status message"""
    if status == 'success':
        print(f"{Colors.GREEN}✓{Colors.RESET} {message}")
    elif status == 'error':
        print(f"{Colors.RED}✗{Colors.RESET} {message}")
    elif status == 'warning':
        print(f"{Colors.YELLOW}⚠{Colors.RESET} {message}")
    else:
        print(f"{Colors.BLUE}ℹ{Colors.RESET} {message}")


def print_header(text):
    """Print section header"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'=' * 70}{Colors.RESET}")
    print(f"{Colors.BOLD}{text}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'=' * 70}{Colors.RESET}\n")


def check_python_version():
    """Check if Python version meets requirements"""
    print_header("Checking Python Version")
    
    version_info = sys.version_info
    version_str = f"{version_info.major}.{version_info.minor}.{version_info.micro}"
    
    print_status(f"Python version: {version_str}", 'info')
    
    if version_info >= (3, 8):
        print_status(f"Python version {version_str} meets requirements (>= 3.8)", 'success')
        return True
    else:
        print_status(f"Python version {version_str} is too old. Required: >= 3.8", 'error')
        return False


def check_virtual_env():
    """Check if running in a virtual environment"""
    print_header("Checking Virtual Environment")
    
    in_venv = hasattr(sys, 'real_prefix') or (
        hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix
    )
    
    if in_venv:
        print_status("Running in a virtual environment", 'success')
        print_status(f"Virtual environment path: {sys.prefix}", 'info')
        return True
    else:
        print_status("Not running in a virtual environment", 'warning')
        print_status("It is recommended to use a virtual environment", 'warning')
        return False


def check_package(package_name, import_name=None):
    """Check if a Python package is installed"""
    if import_name is None:
        import_name = package_name.replace('-', '_')
    
    try:
        importlib.import_module(import_name)
        print_status(f"{package_name}: Installed", 'success')
        return True
    except ImportError:
        print_status(f"{package_name}: NOT installed", 'error')
        return False


def check_required_packages():
    """Check all required Python packages"""
    print_header("Checking Required Python Packages")
    
    packages = [
        ('dnspython', 'dns'),
        ('requests', 'requests'),
        ('beautifulsoup4', 'bs4'),
        ('jinja2', 'jinja2'),
        ('colorama', 'colorama'),
        ('python-nmap', 'nmap'),
        ('validators', 'validators'),
        ('tldextract', 'tldextract'),
        ('pyyaml', 'yaml'),
        ('tabulate', 'tabulate'),
        ('shodan', 'shodan'),
        ('python-whois', 'whois'),
        ('builtwith', 'builtwith'),
        ('markdown', 'markdown'),
        ('click', 'click'),
        ('rich', 'rich'),
        ('tqdm', 'tqdm'),
        ('python-dateutil', 'dateutil'),
    ]
    
    all_installed = True
    for package_name, import_name in packages:
        if not check_package(package_name, import_name):
            all_installed = False
    
    return all_installed


def check_nmap():
    """Check if nmap is installed and accessible"""
    print_header("Checking External Tools")
    
    try:
        result = subprocess.run(
            ['nmap', '--version'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            version_line = result.stdout.split('\n')[0]
            print_status(f"nmap: Installed - {version_line}", 'success')
            return True
        else:
            print_status("nmap: Found but not working correctly", 'error')
            return False
    except FileNotFoundError:
        print_status("nmap: NOT installed", 'error')
        print_status("Install nmap: sudo apt install nmap (Linux) or brew install nmap (macOS)", 'info')
        return False
    except subprocess.TimeoutExpired:
        print_status("nmap: Command timed out", 'error')
        return False


def check_project_files():
    """Check if required project files exist"""
    print_header("Checking Project Files")
    
    required_files = [
        'main.py',
        'interactive.py',
        'requirements.txt',
        'config.yaml',
        'README.md',
    ]
    
    all_exist = True
    for filename in required_files:
        filepath = Path(filename)
        if filepath.exists():
            print_status(f"{filename}: Found", 'success')
        else:
            print_status(f"{filename}: NOT found", 'error')
            all_exist = False
    
    return all_exist


def check_framework_functionality():
    """Check if the framework can be imported and run"""
    print_header("Checking Framework Functionality")
    
    try:
        # Try to run main.py with --version flag
        result = subprocess.run(
            [sys.executable, 'main.py', '--version'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            print_status(f"Framework test: {result.stdout.strip()}", 'success')
            return True
        else:
            error_msg = result.stderr.strip() if result.stderr.strip() else "Unknown error"
            print_status(f"Framework test failed: {error_msg}", 'error')
            return False
    except FileNotFoundError:
        print_status("main.py not found in current directory", 'error')
        return False
    except subprocess.TimeoutExpired:
        print_status("Framework test timed out", 'error')
        return False
    except Exception as e:
        print_status(f"Framework test error: {str(e)}", 'error')
        return False


def main():
    """Main verification function"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}")
    print("╔════════════════════════════════════════════════════════════════════╗")
    print("║     Red Team Automation Framework - Installation Verification     ║")
    print("╚════════════════════════════════════════════════════════════════════╝")
    print(Colors.RESET)
    
    # Critical checks - must pass for framework to work
    critical_results = {
        'Python Version': check_python_version(),
        'Required Packages': check_required_packages(),
        'Project Files': check_project_files(),
        'Framework Functionality': check_framework_functionality(),
    }
    
    # Optional checks - recommended but not required
    optional_results = {
        'Virtual Environment': check_virtual_env(),
        'External Tools (nmap)': check_nmap(),
    }
    
    # Summary
    print_header("Verification Summary")
    
    print(f"{Colors.BOLD}Critical Checks:{Colors.RESET}")
    critical_passed = sum(1 for v in critical_results.values() if v)
    critical_total = len(critical_results)
    
    for check_name, passed_check in critical_results.items():
        status = 'success' if passed_check else 'error'
        print_status(f"{check_name}: {'PASSED' if passed_check else 'FAILED'}", status)
    
    print(f"\n{Colors.BOLD}Optional Checks:{Colors.RESET}")
    optional_passed = sum(1 for v in optional_results.values() if v)
    optional_total = len(optional_results)
    
    for check_name, passed_check in optional_results.items():
        status = 'success' if passed_check else 'warning'
        result_text = 'PASSED' if passed_check else 'RECOMMENDED'
        print_status(f"{check_name}: {result_text}", status)
    
    summary_text = (
        f"\n{Colors.BOLD}Critical: {critical_passed}/{critical_total} passed | "
        f"Optional: {optional_passed}/{optional_total} passed{Colors.RESET}\n"
    )
    print(summary_text)
    
    # Framework is functional if all critical checks pass
    if critical_passed == critical_total:
        print(f"{Colors.GREEN}{Colors.BOLD}")
        print("╔════════════════════════════════════════════════════════════════════╗")
        print("║          ✓ Installation verified! Framework is ready.             ║")
        print("╚════════════════════════════════════════════════════════════════════╝")
        print(Colors.RESET)
        
        if optional_passed < optional_total:
            print(f"\n{Colors.YELLOW}Note: Some optional checks failed. The framework will work, but:")
            if not optional_results.get('Virtual Environment'):
                print("  • Using a virtual environment is strongly recommended")
            if not optional_results.get('External Tools (nmap)'):
                print("  • nmap is required for port scanning features")
            print(Colors.RESET)
        
        print("\nYou can now use the framework:")
        print("  • Interactive mode: python interactive.py")
        print("  • Command line: python main.py -t <target>")
        print("  • Help: python main.py --help\n")
        return 0
    else:
        print(f"{Colors.RED}{Colors.BOLD}")
        print("╔════════════════════════════════════════════════════════════════════╗")
        print("║   ✗ Critical checks failed. Please review the errors above.       ║")
        print("╚════════════════════════════════════════════════════════════════════╝")
        print(Colors.RESET)
        print("\nRefer to INSTALLATION.md for detailed installation instructions.\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
