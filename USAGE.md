# Red Team Automation Framework - Usage Examples

## Test Targets (For Educational Use Only)

**⚠️ WARNING: Only scan systems you own or have explicit written authorization to test!**

### Safe Testing Environments

1. **Local Testing:**
   ```bash
   # Scan localhost
   python main.py -t 127.0.0.1 --skip-auth
   
   # Scan local network (ensure you own it)
   python main.py -t 192.168.1.1 --skip-auth
   ```

2. **Intentionally Vulnerable VMs:**
   - Metasploitable2
   - DVWA (Damn Vulnerable Web Application)
   - WebGoat
   - HackTheBox (with VPN)
   - TryHackMe

3. **Bug Bounty Platforms:**
   - HackerOne (follow their rules)
   - Bugcrowd (read scope carefully)
   - YesWeHack

### Example Scans

#### Reconnaissance Only
```bash
python main.py -t scanme.nmap.org -m recon
```

#### Port Scan Only
```bash
python main.py -t scanme.nmap.org -m scan
```

#### Full Assessment
```bash
python main.py -t scanme.nmap.org --full
```

#### Custom Configuration
```bash
python main.py -t example.com -c custom_config.yaml
```

### Understanding Output

The tool generates two types of reports:

1. **HTML Report** - Professional report for management/CISO
   - Located in `reports/` directory
   - Open in web browser
   - Includes executive summary, findings, MITRE mapping

2. **JSON Report** - Machine-readable for automation
   - Located in `reports/` directory
   - Can be parsed by other tools
   - Contains complete assessment data

### Exit Codes

- `0` - Success, no high/critical findings
- `1` - High severity findings detected
- `2` - Critical findings detected
- `130` - User interrupted (Ctrl+C)

### Tips

1. **Start Small**: Begin with reconnaissance only on authorized targets
2. **Review Config**: Customize `config.yaml` for your needs
3. **Check Logs**: Review `logs/redteam.log` for detailed information
4. **Read Reports**: HTML reports are designed for decision-makers
5. **Be Responsible**: Always follow responsible disclosure

### Legal Targets for Practice

- **scanme.nmap.org** - Nmap's official scan test server
- **testphp.vulnweb.com** - Acunetix test site
- **Your own systems** - Best option!

Remember: **Just because you can scan something doesn't mean you should or legally can!**
