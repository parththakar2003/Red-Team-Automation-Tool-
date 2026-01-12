# Quick Start Guide

Get up and running with the Red Team Automation Framework in minutes!

## 🚀 Installation (5 Minutes)

### Step 1: Install Prerequisites

**Python 3.8+**
```bash
python3 --version  # Should be 3.8 or higher
```

**Nmap**
```bash
# Linux (Debian/Ubuntu)
sudo apt-get install nmap

# Linux (RedHat/CentOS)
sudo yum install nmap

# macOS
brew install nmap
```

### Step 2: Clone and Setup

```bash
# Clone repository
git clone https://github.com/parththakar2003/Red-Team-Automation-Tool-.git
cd Red-Team-Automation-Tool-

# Create and activate a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install Python dependencies
pip3 install -r requirements.txt
```

**Important:** On modern Linux distributions (Kali Linux, Ubuntu 23.04+), you **must** use a virtual environment due to PEP 668 externally-managed environment restrictions.

**If you see an "externally-managed-environment" error:**
- You need to use a virtual environment (recommended, see above)
- Or install with `pip install --user -r requirements.txt`
- Or use `pipx` for application installation

### Step 3: Verify Installation

```bash
# Run comprehensive verification (recommended)
python3 verify_installation.py

# Or quick version check
python3 main.py --version
```

You should see: `Red Team Automation Framework v1.0.0`

The verification script checks:
- ✓ Python version and packages
- ✓ Project files and functionality  
- ⚠ Virtual environment (recommended)
- ⚠ External tools (nmap)

**Note:** Always activate the virtual environment before running the tool:
```bash
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

## 🎯 Quick Usage

### Option 1: Interactive Mode (Recommended for Beginners)

```bash
# Activate virtual environment first
source venv/bin/activate  # On Windows: venv\Scripts\activate

python3 interactive.py
```

Follow the menu:
1. Choose assessment type
2. Enter target
3. Confirm and run!

### Option 2: Command Line (For Power Users)

```bash
# Activate virtual environment first
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Quick scan
python3 main.py -t example.com -m recon scan --skip-auth

# Full assessment
python3 main.py -t example.com --full --skip-auth
```

## 📊 Understanding Results

### Console Output

After the scan, you'll see:
- ✅ Findings summary (Critical/High/Medium/Low)
- 📄 Report locations
- ⏱️ Scan duration

### Reports

Check the `reports/` directory:
- **HTML Report** - Open in browser, share with management
- **JSON Report** - Machine-readable, integrate with tools

## ⚡ Common Tasks

### Scan a Local Network

```bash
python3 main.py -t 192.168.1.0/24 -m recon scan --skip-auth
```

### Scan a Website

```bash
python3 main.py -t https://example.com --full --skip-auth
```

### Generate JSON Only

```bash
python3 main.py -t example.com --json-only --skip-auth
```

### Quiet Mode (Scripts)

```bash
python3 main.py -t example.com --quiet --skip-auth
```

## 🛠️ Customization

### Edit Configuration

```bash
nano config.yaml
```

Key settings:
- `scan.timeout` - Increase for slow networks
- `scan.max_threads` - Adjust for performance
- `reporting.output_dir` - Change report location

### Custom Wordlists

Edit in `config.yaml`:
```yaml
recon:
  subdomain_wordlist_size: "large"  # small, medium, large

enumeration:
  directory_wordlist_size: "medium"
```

## 🎓 Learning Path

1. **Start Simple**: Use interactive mode on localhost
2. **Read Reports**: Understand HTML report structure
3. **Try Modules**: Test individual modules with `-m`
4. **Go Full**: Run complete assessments with `--full`
5. **Customize**: Adjust config.yaml to your needs

## 🔍 Troubleshooting

### "externally-managed-environment" Error

This occurs on modern Linux distributions (Kali Linux, Ubuntu 23.04+) due to PEP 668.

**Solution (Recommended):**
```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

**Alternative Solutions:**
```bash
# Option 1: Install in user directory
pip install --user -r requirements.txt

# Option 2: Use pipx (for application-style installation)
pipx install .
```

### "Module not found" Error

```bash
# Ensure virtual environment is activated
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### "Nmap not found" Error

```bash
# Install nmap as shown in Step 1
sudo apt-get install nmap  # Linux
brew install nmap          # macOS
```

### Permission Denied

```bash
# Some scans need elevated privileges
sudo python3 main.py -t target --skip-auth
```

### Slow Scans

Edit `config.yaml`:
```yaml
scan:
  max_threads: 20  # Increase from 10
  timeout: 60      # Increase if needed
```

## 📚 Next Steps

- Read `USAGE.md` for detailed examples
- Check `ARCHITECTURE.md` for technical details
- Review `config.yaml` for all options
- Explore individual modules in `modules/`

## ⚠️ Important Reminders

1. **Get Authorization**: Always obtain written permission
2. **Legal Compliance**: Know your local laws
3. **Ethical Use**: No exploitation, only assessment
4. **Responsible Disclosure**: Report findings properly

## 🆘 Getting Help

- Run `python3 main.py --help` for options
- Use interactive mode for guided experience
- Check documentation files
- Review example scans in `USAGE.md`

## 🎉 You're Ready!

Start with a safe target:

```bash
python3 interactive.py
```

Choose "Quick Scan" and enter `127.0.0.1` to test on localhost.

Happy (ethical) hacking! 🛡️
