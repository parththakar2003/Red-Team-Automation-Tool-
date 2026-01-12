# Red Team Automation Tool

A **professional, company-grade Red Team Attack Automation Framework** designed for authorized security testing, educational purposes, and enterprise security assessments.

## 🎯 Overview

This framework simulates real-world Red Team operations following the **Red Team Kill Chain** methodology:

```
Reconnaissance → Scanning → Enumeration → Vulnerability Mapping → Risk Analysis → Reporting
```

The tool provides comprehensive security assessment capabilities with:
- ✅ Professional CISO-ready HTML reports
- ✅ MITRE ATT&CK framework mapping
- ✅ CVE vulnerability identification
- ✅ Risk analysis and scoring
- ✅ Proof-of-exposure (no exploitation)
- ✅ Ethical and legal compliance focus

## ⚠️ Important Legal & Ethical Notice

**FOR AUTHORIZED TESTING ONLY**

- ❌ Unauthorized scanning is **ILLEGAL**
- ✅ Obtain **written authorization** before any assessment
- ✅ Use only in **lab environments** or with explicit permission
- ✅ **Educational purposes** and authorized penetration testing only
- ✅ **No exploitation** - proof-of-exposure only

**You are responsible for ensuring legal compliance in your jurisdiction.**

## 🏗️ Architecture

```
Red-Team-Automation-Tool/
├── core/                      # Core framework components
│   ├── config.py             # Configuration management
│   ├── logger.py             # Logging utilities
│   ├── models.py             # Data models
│   └── orchestrator.py       # Main orchestrator
├── modules/                   # Functional modules
│   ├── recon/                # Reconnaissance
│   │   ├── dns_enum.py       # DNS enumeration
│   │   └── subdomain_discovery.py
│   ├── scan/                 # Port scanning
│   │   └── port_scanner.py
│   ├── enum/                 # Enumeration
│   │   ├── web_tech.py       # Web technology identification
│   │   └── directory_enum.py
│   ├── vuln/                 # Vulnerability mapping
│   │   ├── cve_mapper.py     # CVE identification
│   │   ├── misconfig_checker.py
│   │   └── risk_analyzer.py
│   └── mitre/                # MITRE ATT&CK
│       └── attack_mapper.py
├── reporting/                 # Report generation
│   └── html_generator.py     # HTML/JSON reports
├── utils/                     # Utilities
│   └── banner.py             # CLI utilities
├── config.yaml               # Configuration file
├── main.py                   # CLI entry point
└── requirements.txt          # Python dependencies
```

## 🚀 Installation

For detailed installation instructions including troubleshooting and platform-specific guides, see [INSTALLATION.md](INSTALLATION.md).

### Prerequisites

- Python 3.8 or higher
- pip package manager
- nmap (for port scanning)

### Install nmap

**Linux (Debian/Ubuntu):**
```bash
sudo apt-get update
sudo apt-get install nmap
```

**Linux (RedHat/CentOS):**
```bash
sudo yum install nmap
```

**macOS:**
```bash
brew install nmap
```

**Windows:**
Download from https://nmap.org/download.html

### Install Python Dependencies

```bash
# Clone the repository
git clone https://github.com/parththakar2003/Red-Team-Automation-Tool-.git
cd Red-Team-Automation-Tool-

# Create and activate a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

**Note:** On modern Linux distributions (like Kali Linux, Ubuntu 23.04+), Python environments are externally managed (PEP 668). Using a virtual environment is **strongly recommended** to avoid installation errors.

**Alternative:** If you prefer not to use a virtual environment, you can use:
```bash
pip install --user -r requirements.txt
# Or (WARNING: may break system Python): pip install --break-system-packages -r requirements.txt
```

## 📖 Usage

### Interactive Mode (Easiest!)

For the most user-friendly experience, use the interactive menu:

```bash
# If using virtual environment, make sure it's activated first
# source venv/bin/activate  # On Windows: venv\Scripts\activate

python interactive.py
```

This provides a guided menu with:
- 🎯 Quick scan options
- 📋 Standard and full assessments  
- 🎨 Custom module selection
- 📚 Built-in help
- ✨ Beautiful CLI interface

### Command Line Mode

#### Basic Scan

```bash
python main.py -t example.com
```

#### Scan Specific IP

```bash
python main.py -t 192.168.1.100
```

#### Run Specific Modules

```bash
python main.py -t example.com -m recon scan enum
```

#### Full Assessment

```bash
python main.py -t example.com --full
```

#### Skip Authorization Prompt (Use Carefully!)

```bash
python main.py -t example.com --skip-auth
```

#### Quiet Mode (Minimal Output)

```bash
python main.py -t example.com --quiet
```

#### Show Findings Table

```bash
python main.py -t example.com --show-findings
```

#### Generate JSON Report Only

```bash
python main.py -t example.com --json-only
```

### Command Line Options

```
-t, --target       Target to assess (IP, domain, or CIDR)
-m, --modules      Modules to run (recon, scan, enum, vuln, risk)
--full             Run full assessment with all modules
--skip-auth        Skip authorization confirmation
--no-report        Skip report generation
--json-only        Generate JSON report only
--show-findings    Display findings table in console
-o, --output       Output directory for reports
-c, --config       Path to custom config file
-v, --verbose      Enable verbose output
-q, --quiet        Quiet mode - minimal output
--version          Show version information
```

## 🔍 Features

### 1️⃣ Reconnaissance Module

- DNS enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME)
- Subdomain discovery (passive & active)
- IP resolution and reverse DNS
- Certificate transparency log searches
- WHOIS data collection

### 2️⃣ Scanning Module

- TCP/UDP port scanning
- Service detection and version identification
- Banner grabbing
- OS fingerprinting
- Smart service enumeration

### 3️⃣ Enumeration Module

- Web technology fingerprinting
- CMS detection (WordPress, Joomla, Drupal)
- Framework identification (React, Angular, Django, etc.)
- Directory and endpoint discovery
- SSL/TLS configuration analysis
- Security header checks

### 4️⃣ Vulnerability Mapping Module

- CVE database lookup
- Known vulnerability identification
- Misconfiguration detection
- Weak security practice identification
- CVSS scoring
- Proof-of-exposure generation

### 5️⃣ MITRE ATT&CK Mapping

- Automatic technique mapping
- Tactic identification
- Attack path visualization
- Enterprise technique coverage

### 6️⃣ Risk Analysis Engine

- CVSS-based severity classification
- Business impact assessment
- Risk scoring and prioritization
- Remediation guidance

### 7️⃣ Professional Reporting

**HTML Reports Include:**
- Executive summary for management
- Risk dashboard with severity counts
- Detailed findings with evidence
- MITRE ATT&CK mapping
- Remediation recommendations
- Professional CISO-ready format

**JSON Reports Include:**
- Machine-readable format
- Complete assessment data
- Integration-ready structure

## ⚙️ Configuration

Edit `config.yaml` to customize:

- Scan timeouts and rate limits
- Port ranges and wordlists
- DNS servers
- Reporting options
- Risk thresholds
- Module-specific settings

## 📊 Sample Output

```
╔═══════════════════════════════════════════════════════════════════════╗
║                     RED TEAM AUTOMATION FRAMEWORK                     ║
╚═══════════════════════════════════════════════════════════════════════╝

Target: example.com
Session ID: a1b2c3d4

===========================================================================
  Assessment Complete
===========================================================================

Findings Summary:
  • Critical: 2
  • High:     5
  • Medium:   8
  • Low:      3
  • Total:    18

Reports Generated:
  ✓ HTML Report: reports/redteam_report_example.com_20260112.html
  ✓ JSON Report: reports/redteam_report_example.com_20260112.json
```

## 🎓 Educational Value

This project demonstrates:

- **Software Architecture**: Clean, modular design patterns
- **Security Concepts**: Real-world Red Team methodology
- **Python Development**: Professional coding practices
- **Automation**: Efficient security testing workflows
- **Documentation**: Comprehensive technical writing

Perfect for:
- Final year projects
- Security portfolios
- Learning Red Team operations
- Understanding offensive security
- Preparing for security interviews

## 🔮 Future Enhancements

- [ ] SIEM integration (Splunk, ELK)
- [ ] Blue Team detection simulation
- [ ] Cloud asset scanning (AWS, Azure, GCP)
- [ ] Web dashboard UI
- [ ] Automated patch recommendations
- [ ] Custom plugin system
- [ ] Multi-target parallel scanning
- [ ] Continuous monitoring mode

## 🤝 Contributing

This is an educational project. Contributions are welcome:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Submit a pull request

## 📝 License

This project is for **educational and authorized testing purposes only**.

## 👨‍💻 Author

**Security Assessment Team**
- GitHub: [@parththakar2003](https://github.com/parththakar2003)

## 🙏 Acknowledgments

- MITRE ATT&CK Framework
- OWASP Testing Guide
- NIST Cybersecurity Framework
- Red Team community

## 📚 References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST SP 800-115](https://csrc.nist.gov/publications/detail/sp/800-115/final)
- [Red Team Development and Operations](https://redteam.guide/)

---

**⚠️ Remember: With great power comes great responsibility. Use ethically and legally.**