# Installation Guide

This guide provides detailed installation instructions for the Red Team Automation Framework across different operating systems and Python environments.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Virtual Environment Setup (Recommended)](#virtual-environment-setup-recommended)
- [Installation Methods](#installation-methods)
- [Platform-Specific Instructions](#platform-specific-instructions)
- [Troubleshooting](#troubleshooting)
- [Verification](#verification)

## Prerequisites

### Required Software

1. **Python 3.8 or higher**
   ```bash
   python3 --version  # Check your Python version
   ```

2. **pip (Python package manager)**
   ```bash
   pip3 --version  # Check if pip is installed
   ```

3. **nmap (Network scanning tool)**
   - Required for port scanning functionality
   - See platform-specific instructions below

### System Requirements

- Operating System: Linux, macOS, or Windows
- RAM: 2GB minimum (4GB recommended)
- Disk Space: 500MB minimum
- Network: Internet connection for dependency installation

## Virtual Environment Setup (Recommended)

Using a virtual environment is **strongly recommended** and **required** on modern Linux distributions (Kali Linux 2023.1+, Ubuntu 23.04+, Debian 12+) due to PEP 668 externally-managed environment restrictions.

### Why Use a Virtual Environment?

- **Isolation**: Keeps project dependencies separate from system Python
- **Compatibility**: Avoids conflicts with system packages
- **Required**: Mandatory on externally-managed Python environments
- **Best Practice**: Industry standard for Python development

### Creating a Virtual Environment

```bash
# Navigate to project directory
cd Red-Team-Automation-Tool-

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On Linux/macOS:
source venv/bin/activate

# On Windows (Command Prompt):
venv\Scripts\activate.bat

# On Windows (PowerShell):
venv\Scripts\Activate.ps1
```

When activated, you should see `(venv)` in your command prompt.

### Deactivating Virtual Environment

```bash
deactivate
```

## Installation Methods

### Method 1: Virtual Environment (Recommended)

This is the recommended method for all platforms, and **required** for externally-managed Python environments.

```bash
# Clone repository
git clone https://github.com/parththakar2003/Red-Team-Automation-Tool-.git
cd Red-Team-Automation-Tool-

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Verify installation (recommended)
python verify_installation.py

# Quick version check
python main.py --version
```

### Method 2: User Installation (Alternative)

Install packages in user directory without virtual environment:

```bash
# Clone repository
git clone https://github.com/parththakar2003/Red-Team-Automation-Tool-.git
cd Red-Team-Automation-Tool-

# Install in user directory
pip install --user -r requirements.txt

# Run with python3
python3 main.py --version
```

### Method 3: pipx Installation (For Application-Style Usage)

Install as a standalone application using pipx:

```bash
# Install pipx if not already installed
# On Debian/Ubuntu/Kali:
sudo apt install pipx
pipx ensurepath

# On macOS:
brew install pipx
pipx ensurepath

# Install the tool
git clone https://github.com/parththakar2003/Red-Team-Automation-Tool-.git
cd Red-Team-Automation-Tool-
pipx install .

# The tool can then be run from anywhere using the 'redteam' command
# or by running the Python scripts directly
redteam --version
# Or: python3 main.py --version
```

### Method 4: System-Wide (Not Recommended)

**Warning:** This method bypasses PEP 668 protections and may break your system Python. Use only if you understand the risks.

```bash
# On externally-managed systems (Kali, Ubuntu 23.04+)
pip install --break-system-packages -r requirements.txt
```

## Platform-Specific Instructions

### Kali Linux / Debian / Ubuntu

```bash
# Update package list
sudo apt update

# Install Python and pip (if not installed)
sudo apt install python3 python3-pip python3-venv

# Install nmap
sudo apt install nmap

# Clone and setup
git clone https://github.com/parththakar2003/Red-Team-Automation-Tool-.git
cd Red-Team-Automation-Tool-

# Create virtual environment (REQUIRED on Kali 2023.1+)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Red Hat / CentOS / Fedora

```bash
# Install Python and pip
sudo yum install python3 python3-pip

# Install nmap
sudo yum install nmap

# Clone and setup
git clone https://github.com/parththakar2003/Red-Team-Automation-Tool-.git
cd Red-Team-Automation-Tool-

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### macOS

```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python (if not using system Python)
brew install python3

# Install nmap
brew install nmap

# Clone and setup
git clone https://github.com/parththakar2003/Red-Team-Automation-Tool-.git
cd Red-Team-Automation-Tool-

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Windows

```powershell
# Install Python from https://www.python.org/downloads/
# Make sure to check "Add Python to PATH" during installation

# Install nmap from https://nmap.org/download.html

# Open Command Prompt or PowerShell
# Clone repository
git clone https://github.com/parththakar2003/Red-Team-Automation-Tool-.git
cd Red-Team-Automation-Tool-

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Command Prompt:
venv\Scripts\activate.bat
# PowerShell:
venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

**Note for PowerShell Users:** If you get an execution policy error, run:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## Troubleshooting

### "externally-managed-environment" Error

**Problem:** You see this error when running `pip install -r requirements.txt`:
```
error: externally-managed-environment

× This environment is externally managed
```

**Solution:** This is a PEP 668 protection on modern Linux distributions. You **must** use one of these methods:

1. **Virtual Environment (Recommended):**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. **User Installation:**
   ```bash
   pip install --user -r requirements.txt
   ```

3. **pipx (for application-style installation):**
   ```bash
   sudo apt install pipx  # or brew install pipx on macOS
   pipx install .
   ```

### "No module named 'venv'" Error

**Problem:** Virtual environment creation fails.

**Solution:** Install the venv package:
```bash
# Debian/Ubuntu/Kali:
sudo apt install python3-venv

# Fedora/CentOS:
sudo yum install python3-venv
```

### "nmap not found" Error

**Problem:** The tool reports that nmap is not installed.

**Solution:** Install nmap:
```bash
# Linux (Debian/Ubuntu/Kali):
sudo apt install nmap

# Linux (RedHat/CentOS/Fedora):
sudo yum install nmap

# macOS:
brew install nmap

# Windows:
# Download and install from https://nmap.org/download.html
```

### "Permission denied" Errors

**Problem:** Some scans require elevated privileges.

**Solution:** Run with sudo (keep virtual environment activated):
```bash
# Activate virtual environment first
source venv/bin/activate

# Run with sudo, using the virtual environment's Python
sudo $(which python) main.py -t target --skip-auth
```

### Import Errors After Installation

**Problem:** You get "ModuleNotFoundError" when running the tool.

**Solution:** 
1. Make sure virtual environment is activated (you should see `(venv)` in prompt)
2. Reinstall dependencies:
   ```bash
   source venv/bin/activate
   pip install --force-reinstall -r requirements.txt
   ```

### Slow Installation

**Problem:** Dependency installation is taking too long.

**Solution:** Use a faster mirror or upgrade pip:
```bash
pip install --upgrade pip
pip install -r requirements.txt --use-feature=fast-deps
```

## Verification

After installation, verify everything works:

### Quick Verification

```bash
# Activate virtual environment (if using one)
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Check version
python main.py --version

# Expected output:
# Red Team Automation Framework v1.0.0
```

### Comprehensive Verification (Recommended)

Use the built-in verification script to check all components:

```bash
# Activate virtual environment (if using one)
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Run verification script
python verify_installation.py
```

The verification script checks:
- ✓ Python version compatibility
- ✓ All required Python packages
- ✓ Project file integrity
- ✓ Framework functionality
- ⚠ Virtual environment usage (recommended)
- ⚠ External tools (nmap)

### Manual Verification

```bash
# Verify nmap is accessible
nmap --version

# Run a simple test
python main.py -t 127.0.0.1 -m recon --skip-auth
```

## Daily Usage

Every time you want to use the tool:

```bash
# Navigate to project directory
cd Red-Team-Automation-Tool-

# Activate virtual environment
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Run the tool
python main.py -t target
# or
python interactive.py

# When done, deactivate
deactivate
```

## Updating Dependencies

To update dependencies to their latest versions:

```bash
# Activate virtual environment
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Update all dependencies
pip install --upgrade -r requirements.txt
```

## Uninstallation

To completely remove the tool:

```bash
# Remove virtual environment
rm -rf venv/

# Remove project directory
cd ..
rm -rf Red-Team-Automation-Tool-/
```

## Getting Help

If you encounter issues not covered here:

1. Check the [README.md](README.md) for general documentation
2. Review [QUICKSTART.md](QUICKSTART.md) for quick setup
3. Read [USAGE.md](USAGE.md) for usage examples
4. Open an issue on GitHub with:
   - Your operating system and version
   - Python version (`python3 --version`)
   - Complete error message
   - Installation method used

## Best Practices

1. **Always use a virtual environment** for Python projects
2. **Keep dependencies updated** for security patches
3. **Don't use `--break-system-packages`** unless absolutely necessary
4. **Document your setup** for team members
5. **Test in a safe environment** before production use

---

**Ready to start?** Head to [QUICKSTART.md](QUICKSTART.md) for a quick 5-minute setup guide!
