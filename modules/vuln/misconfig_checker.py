"""
Misconfiguration Checker Module
Identifies common security misconfigurations
"""
from typing import List
from core.logger import Logger
from core.config import get_config
from core.models import Finding, FindingCategory, RiskLevel, ScanSession


class MisconfigurationChecker:
    """Check for common security misconfigurations"""
    
    def __init__(self):
        """Initialize misconfiguration checker"""
        self.logger = Logger.get(__name__)
        self.config = get_config()
    
    def check(self, session: ScanSession) -> List[Finding]:
        """
        Check for misconfigurations in scan results
        
        Args:
            session: ScanSession with scan data
            
        Returns:
            List of misconfiguration findings
        """
        self.logger.info("Checking for security misconfigurations")
        
        findings = []
        
        # Check port-related misconfigurations
        if session.scan_results:
            findings.extend(self._check_port_misconfigs(session))
        
        # Check web-related misconfigurations
        if session.enum_results:
            findings.extend(self._check_web_misconfigs(session))
        
        # Check SSL/TLS misconfigurations
        if session.enum_results and session.enum_results.ssl_info:
            findings.extend(self._check_ssl_misconfigs(session))
        
        self.logger.info(f"Found {len(findings)} misconfiguration issues")
        
        return findings
    
    def _check_port_misconfigs(self, session: ScanSession) -> List[Finding]:
        """Check for port-related misconfigurations"""
        findings = []
        
        open_ports = [p for p in session.scan_results.ports if p.state == 'open']
        
        # Check for unnecessary exposed services
        risky_services = {
            'telnet': {
                'title': 'Telnet Service Exposed',
                'severity': RiskLevel.HIGH,
                'description': 'Telnet is an insecure protocol that transmits data in cleartext',
                'remediation': 'Disable Telnet service and use SSH for remote access'
            },
            'ftp': {
                'title': 'FTP Service Exposed',
                'severity': RiskLevel.MEDIUM,
                'description': 'Plain FTP transmits credentials in cleartext',
                'remediation': 'Use SFTP or FTPS instead of plain FTP'
            },
            'smb': {
                'title': 'SMB Service Exposed to Internet',
                'severity': RiskLevel.HIGH,
                'description': 'SMB should not be exposed to the internet due to historical vulnerabilities',
                'remediation': 'Restrict SMB access to internal networks only'
            },
            'rdp': {
                'title': 'RDP Exposed to Internet',
                'severity': RiskLevel.HIGH,
                'description': 'RDP is a frequent target for brute force and ransomware attacks',
                'remediation': 'Use VPN for remote access or implement strong MFA'
            },
            'mysql': {
                'title': 'Database Service Exposed',
                'severity': RiskLevel.HIGH,
                'description': 'Database should not be directly accessible from the internet',
                'remediation': 'Restrict database access to application servers only'
            },
            'postgresql': {
                'title': 'Database Service Exposed',
                'severity': RiskLevel.HIGH,
                'description': 'Database should not be directly accessible from the internet',
                'remediation': 'Restrict database access to application servers only'
            },
            'mongodb': {
                'title': 'Database Service Exposed',
                'severity': RiskLevel.HIGH,
                'description': 'Database should not be directly accessible from the internet',
                'remediation': 'Restrict database access to application servers only'
            }
        }
        
        for port in open_ports:
            if port.service in risky_services:
                config = risky_services[port.service]
                
                finding = Finding(
                    id=f"MISCONFIG-{len(findings)+1:03d}",
                    title=config['title'],
                    category=FindingCategory.MISCONFIGURATION,
                    severity=config['severity'],
                    description=config['description'],
                    affected_target=session.target.identifier,
                    affected_component=f"Port {port.number}/{port.protocol}",
                    proof_of_exposure=f"Service {port.service} is accessible on port {port.number}",
                    business_impact=f"Exposed {port.service} service increases risk of unauthorized access and data breach",
                    remediation=config['remediation']
                )
                findings.append(finding)
        
        # Check for too many open ports
        if len(open_ports) > 20:
            finding = Finding(
                id=f"MISCONFIG-{len(findings)+1:03d}",
                title="Excessive Number of Open Ports",
                category=FindingCategory.MISCONFIGURATION,
                severity=RiskLevel.MEDIUM,
                description=f"System has {len(open_ports)} open ports, which increases attack surface",
                affected_target=session.target.identifier,
                proof_of_exposure=f"Total open ports: {len(open_ports)}",
                business_impact="Large attack surface increases risk of exploitation",
                remediation="Close unnecessary ports and services. Follow principle of least privilege."
            )
            findings.append(finding)
        
        return findings
    
    def _check_web_misconfigs(self, session: ScanSession) -> List[Finding]:
        """Check for web-related misconfigurations"""
        findings = []
        
        enum_results = session.enum_results
        
        # Check security headers
        if enum_results.headers:
            security_headers = {
                'strict-transport-security': 'HSTS',
                'x-frame-options': 'X-Frame-Options',
                'x-content-type-options': 'X-Content-Type-Options',
                'x-xss-protection': 'X-XSS-Protection',
                'content-security-policy': 'Content-Security-Policy'
            }
            
            missing_headers = []
            for header_key, header_name in security_headers.items():
                if header_key not in [k.lower() for k in enum_results.headers.keys()]:
                    missing_headers.append(header_name)
            
            if missing_headers:
                finding = Finding(
                    id=f"MISCONFIG-{len(findings)+1:03d}",
                    title="Missing Security Headers",
                    category=FindingCategory.MISCONFIGURATION,
                    severity=RiskLevel.MEDIUM,
                    description=f"Web application is missing important security headers: {', '.join(missing_headers)}",
                    affected_target=session.target.identifier,
                    affected_component=enum_results.target,
                    proof_of_exposure=f"Missing headers: {', '.join(missing_headers)}",
                    business_impact="Missing security headers can lead to XSS, clickjacking, and other attacks",
                    remediation="Implement recommended security headers in web server configuration"
                )
                findings.append(finding)
        
        # Check for exposed sensitive endpoints
        sensitive_endpoints = ['/admin', '/.git/config', '/.env', '/phpinfo.php', '/config.php']
        exposed_sensitive = [ep for ep in enum_results.endpoints if any(s in ep for s in sensitive_endpoints)]
        
        if exposed_sensitive:
            finding = Finding(
                id=f"MISCONFIG-{len(findings)+1:03d}",
                title="Exposed Sensitive Endpoints",
                category=FindingCategory.MISCONFIGURATION,
                severity=RiskLevel.HIGH,
                description=f"Sensitive endpoints are publicly accessible",
                affected_target=session.target.identifier,
                affected_component=enum_results.target,
                proof_of_exposure=f"Exposed endpoints: {', '.join(exposed_sensitive)}",
                business_impact="Exposed sensitive files can lead to information disclosure or unauthorized access",
                remediation="Remove or restrict access to sensitive files and directories"
            )
            findings.append(finding)
        
        # Check for Server header disclosure
        if enum_results.headers.get('Server'):
            server_value = enum_results.headers['Server']
            # Check if version is disclosed
            if any(char.isdigit() for char in server_value):
                finding = Finding(
                    id=f"MISCONFIG-{len(findings)+1:03d}",
                    title="Server Version Disclosure",
                    category=FindingCategory.MISCONFIGURATION,
                    severity=RiskLevel.LOW,
                    description="Server header reveals version information",
                    affected_target=session.target.identifier,
                    affected_component=enum_results.target,
                    proof_of_exposure=f"Server: {server_value}",
                    business_impact="Version disclosure aids attackers in identifying specific vulnerabilities",
                    remediation="Configure web server to suppress version information in headers"
                )
                findings.append(finding)
        
        return findings
    
    def _check_ssl_misconfigs(self, session: ScanSession) -> List[Finding]:
        """Check for SSL/TLS misconfigurations"""
        findings = []
        
        ssl_info = session.enum_results.ssl_info
        
        # Check SSL version
        if 'version' in ssl_info:
            version = ssl_info['version']
            if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                finding = Finding(
                    id=f"MISCONFIG-{len(findings)+1:03d}",
                    title="Weak SSL/TLS Version",
                    category=FindingCategory.MISCONFIGURATION,
                    severity=RiskLevel.HIGH,
                    description=f"Server supports weak SSL/TLS version: {version}",
                    affected_target=session.target.identifier,
                    affected_component=session.enum_results.target,
                    proof_of_exposure=f"SSL/TLS Version: {version}",
                    business_impact="Weak SSL/TLS versions are vulnerable to protocol downgrade attacks",
                    remediation="Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1. Use TLS 1.2 or higher."
                )
                findings.append(finding)
        
        # Check cipher suite
        if 'cipher' in ssl_info and ssl_info['cipher']:
            cipher_name = ssl_info['cipher'][0] if isinstance(ssl_info['cipher'], tuple) else str(ssl_info['cipher'])
            weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL']
            
            if any(weak in cipher_name.upper() for weak in weak_ciphers):
                finding = Finding(
                    id=f"MISCONFIG-{len(findings)+1:03d}",
                    title="Weak Cipher Suite",
                    category=FindingCategory.MISCONFIGURATION,
                    severity=RiskLevel.MEDIUM,
                    description=f"Server supports weak cipher suite",
                    affected_target=session.target.identifier,
                    affected_component=session.enum_results.target,
                    proof_of_exposure=f"Cipher: {cipher_name}",
                    business_impact="Weak ciphers can be broken, compromising confidentiality",
                    remediation="Configure server to use strong cipher suites only (AES-GCM, ChaCha20)"
                )
                findings.append(finding)
        
        return findings
