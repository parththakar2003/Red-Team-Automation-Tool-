"""
Core Orchestrator - Coordinates all modules in the Red Team workflow
"""
import uuid
from datetime import datetime
from typing import Optional
from core.config import get_config
from core.logger import Logger
from core.models import Target, ScanSession, Finding, RiskLevel, FindingCategory
from modules.recon.dns_enum import DNSEnumerator
from modules.recon.subdomain_discovery import SubdomainDiscovery
from modules.scan.port_scanner import PortScanner
from modules.enum.web_tech import WebTechIdentifier
from modules.enum.directory_enum import DirectoryEnumerator
from modules.vuln.cve_mapper import CVEMapper
from modules.vuln.misconfig_checker import MisconfigurationChecker
from modules.mitre.attack_mapper import MITREMapper
from modules.vuln.risk_analyzer import RiskAnalyzer


class RedTeamOrchestrator:
    """
    Main orchestrator that coordinates the Red Team Kill Chain:
    Reconnaissance → Scanning → Enumeration → Vulnerability Mapping → Risk Analysis
    """
    
    def __init__(self):
        """Initialize orchestrator"""
        self.config = get_config()
        self.logger = Logger.get(__name__)
        self.session: Optional[ScanSession] = None
        
    def run_assessment(self, target_str: str, modules: list = None) -> ScanSession:
        """
        Run complete security assessment
        
        Args:
            target_str: Target identifier (IP, domain, or CIDR)
            modules: List of modules to run (default: all)
            
        Returns:
            ScanSession with results
        """
        # Initialize session
        session_id = str(uuid.uuid4())[:8]
        target = self._parse_target(target_str)
        
        self.session = ScanSession(
            session_id=session_id,
            target=target,
            start_time=datetime.now()
        )
        
        self.logger.info(f"Starting Red Team assessment [Session: {session_id}]")
        self.logger.info(f"Target: {target_str}")
        
        # Default to all modules
        if modules is None:
            modules = ['recon', 'scan', 'enum', 'vuln', 'risk']
        
        try:
            # Phase 1: Reconnaissance
            if 'recon' in modules:
                self.logger.info("=" * 60)
                self.logger.info("PHASE 1: RECONNAISSANCE")
                self.logger.info("=" * 60)
                self._run_reconnaissance()
            
            # Phase 2: Scanning
            if 'scan' in modules:
                self.logger.info("=" * 60)
                self.logger.info("PHASE 2: PORT SCANNING & SERVICE DETECTION")
                self.logger.info("=" * 60)
                self._run_scanning()
            
            # Phase 3: Enumeration
            if 'enum' in modules:
                self.logger.info("=" * 60)
                self.logger.info("PHASE 3: ENUMERATION")
                self.logger.info("=" * 60)
                self._run_enumeration()
            
            # Phase 4: Vulnerability Mapping
            if 'vuln' in modules:
                self.logger.info("=" * 60)
                self.logger.info("PHASE 4: VULNERABILITY MAPPING")
                self.logger.info("=" * 60)
                self._run_vulnerability_mapping()
            
            # Phase 5: Risk Analysis
            if 'risk' in modules:
                self.logger.info("=" * 60)
                self.logger.info("PHASE 5: RISK ANALYSIS")
                self.logger.info("=" * 60)
                self._run_risk_analysis()
            
            self.session.end_time = datetime.now()
            self.logger.info("=" * 60)
            self.logger.info(f"Assessment completed in {self.session.duration:.2f} seconds")
            self.logger.info(f"Total findings: {len(self.session.findings)}")
            
            # Display summary
            summary = self.session.get_risk_summary()
            self.logger.info(f"Critical: {summary['critical']}, High: {summary['high']}, "
                           f"Medium: {summary['medium']}, Low: {summary['low']}")
            
        except Exception as e:
            self.logger.error(f"Assessment failed: {e}", exc_info=True)
            self.session.end_time = datetime.now()
            raise
        
        return self.session
    
    def _parse_target(self, target_str: str) -> Target:
        """Parse target string and determine type"""
        import ipaddress
        import validators
        
        target_str = target_str.strip()
        
        # Check if CIDR
        if '/' in target_str:
            try:
                ipaddress.ip_network(target_str, strict=False)
                return Target(identifier=target_str, type='cidr')
            except:
                pass
        
        # Check if IP
        try:
            ipaddress.ip_address(target_str)
            return Target(identifier=target_str, type='ip', ip_addresses=[target_str])
        except:
            pass
        
        # Assume domain
        if validators.domain(target_str):
            return Target(identifier=target_str, type='domain', domains=[target_str])
        
        # Fallback
        return Target(identifier=target_str, type='unknown')
    
    def _run_reconnaissance(self):
        """Execute reconnaissance phase"""
        self.logger.info("Running DNS enumeration...")
        dns_enum = DNSEnumerator()
        recon_result = dns_enum.enumerate(self.session.target.identifier)
        self.session.recon_results = recon_result
        
        # Add findings from recon
        if recon_result.subdomains:
            self.session.findings.append(Finding(
                id=f"RECON-{len(self.session.findings)+1:03d}",
                title=f"Discovered {len(recon_result.subdomains)} Subdomains",
                category=FindingCategory.RECON,
                severity=RiskLevel.INFO,
                description=f"Subdomain discovery revealed {len(recon_result.subdomains)} subdomains for {self.session.target.identifier}",
                affected_target=self.session.target.identifier,
                proof_of_exposure=f"Subdomains: {', '.join(recon_result.subdomains[:5])}...",
                business_impact="Subdomains may expose additional attack surface and internal infrastructure."
            ))
        
        self.logger.info(f"Found {len(recon_result.dns_records)} DNS record types")
        self.logger.info(f"Found {len(recon_result.subdomains)} subdomains")
    
    def _run_scanning(self):
        """Execute scanning phase"""
        target = self.session.target.identifier
        
        self.logger.info("Running port scan...")
        scanner = PortScanner()
        scan_result = scanner.scan(target)
        self.session.scan_results = scan_result
        
        open_ports = [p for p in scan_result.ports if p.state == 'open']
        self.logger.info(f"Found {len(open_ports)} open ports")
        
        # Add findings for exposed services
        for port in open_ports:
            if port.service:
                self.session.findings.append(Finding(
                    id=f"SCAN-{len(self.session.findings)+1:03d}",
                    title=f"Exposed Service: {port.service.upper()} on Port {port.number}",
                    category=FindingCategory.EXPOSURE,
                    severity=self._assess_port_risk(port),
                    description=f"Service {port.service} is exposed on port {port.number}/{port.protocol}",
                    affected_target=target,
                    affected_component=f"Port {port.number}",
                    proof_of_exposure=f"Service: {port.service}, Version: {port.version or 'Unknown'}, Banner: {port.banner or 'N/A'}",
                    business_impact=self._get_service_business_impact(port.service)
                ))
    
    def _run_enumeration(self):
        """Execute enumeration phase"""
        if not self.session.scan_results:
            self.logger.warning("No scan results available for enumeration")
            return
        
        target = self.session.target.identifier
        
        # Check for web services
        web_ports = [p for p in self.session.scan_results.ports 
                    if p.state == 'open' and p.service in ['http', 'https']]
        
        if web_ports:
            self.logger.info("Running web technology identification...")
            web_tech = WebTechIdentifier()
            
            for port in web_ports[:1]:  # Enumerate first web service found
                protocol = 'https' if port.service == 'https' else 'http'
                url = f"{protocol}://{target}:{port.number}"
                
                enum_result = web_tech.identify(url)
                self.session.enum_results = enum_result
                
                # Add findings for web technologies
                for tech in enum_result.web_technologies:
                    self.session.findings.append(Finding(
                        id=f"ENUM-{len(self.session.findings)+1:03d}",
                        title=f"Identified Technology: {tech.name}",
                        category=FindingCategory.RECON,
                        severity=RiskLevel.INFO,
                        description=f"Web technology {tech.name} detected",
                        affected_target=target,
                        affected_component=url,
                        proof_of_exposure=f"Technology: {tech.name}, Version: {tech.version or 'Unknown'}, Category: {tech.category}"
                    ))
                
                self.logger.info(f"Identified {len(enum_result.web_technologies)} web technologies")
        else:
            self.logger.info("No web services found for enumeration")
    
    def _run_vulnerability_mapping(self):
        """Execute vulnerability mapping phase"""
        if not self.session.scan_results:
            self.logger.warning("No scan results for vulnerability mapping")
            return
        
        self.logger.info("Mapping vulnerabilities to discovered services...")
        
        cve_mapper = CVEMapper()
        misconfig_checker = MisconfigurationChecker()
        mitre_mapper = MITREMapper()
        
        # Check for CVEs based on services and versions
        for port in self.session.scan_results.ports:
            if port.state == 'open' and port.service and port.version:
                vulns = cve_mapper.check_service(port.service, port.version)
                
                for vuln in vulns:
                    # Map to MITRE ATT&CK
                    techniques = mitre_mapper.map_vulnerability(vuln)
                    
                    self.session.findings.append(Finding(
                        id=f"VULN-{len(self.session.findings)+1:03d}",
                        title=vuln.title,
                        category=FindingCategory.VULNERABILITY,
                        severity=vuln.severity,
                        description=vuln.description,
                        affected_target=self.session.target.identifier,
                        affected_component=f"{port.service} {port.version} on port {port.number}",
                        proof_of_exposure=vuln.proof_of_exposure,
                        business_impact=self._get_vulnerability_business_impact(vuln.severity),
                        cvss_score=vuln.cvss_score,
                        cve_ids=[vuln.cve_id] if vuln.cve_id else [],
                        mitre_techniques=techniques,
                        remediation=vuln.remediation,
                        references=vuln.references
                    ))
        
        # Check for misconfigurations
        misconfigs = misconfig_checker.check(self.session)
        for misconfig in misconfigs:
            self.session.findings.append(misconfig)
        
        self.logger.info(f"Identified {len([f for f in self.session.findings if f.category == FindingCategory.VULNERABILITY])} vulnerabilities")
    
    def _run_risk_analysis(self):
        """Execute risk analysis phase"""
        self.logger.info("Performing risk analysis...")
        
        analyzer = RiskAnalyzer()
        
        # Analyze and update findings with risk scores
        for finding in self.session.findings:
            analyzer.analyze_finding(finding)
        
        # Sort findings by severity
        severity_order = {
            RiskLevel.CRITICAL: 0,
            RiskLevel.HIGH: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.LOW: 3,
            RiskLevel.INFO: 4
        }
        self.session.findings.sort(key=lambda f: severity_order[f.severity])
        
        summary = self.session.get_risk_summary()
        self.logger.info(f"Risk Analysis Complete - Critical: {summary['critical']}, "
                        f"High: {summary['high']}, Medium: {summary['medium']}, Low: {summary['low']}")
    
    def _assess_port_risk(self, port) -> RiskLevel:
        """Assess risk level for exposed port"""
        high_risk_services = ['ftp', 'telnet', 'smb', 'rdp', 'vnc', 'mysql', 'postgresql', 'mongodb']
        medium_risk_services = ['ssh', 'smtp', 'dns', 'ldap']
        
        if port.service in high_risk_services:
            return RiskLevel.HIGH
        elif port.service in medium_risk_services:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _get_service_business_impact(self, service: str) -> str:
        """Get business impact description for exposed service"""
        impacts = {
            'ftp': "Exposed FTP service may allow unauthorized file access or data exfiltration.",
            'ssh': "SSH exposure increases attack surface for brute force and credential attacks.",
            'telnet': "Telnet transmits data in cleartext, exposing credentials and sensitive data.",
            'smtp': "Exposed SMTP may be leveraged for spam relay or email spoofing.",
            'rdp': "RDP exposure is a common target for ransomware and remote access attacks.",
            'smb': "SMB vulnerabilities have been exploited for lateral movement and ransomware.",
            'http': "Web application exposure may lead to data breaches or service disruption.",
            'https': "Secure web service exposure still requires proper configuration and updates.",
        }
        return impacts.get(service, f"Exposed {service} service increases attack surface.")
    
    def _get_vulnerability_business_impact(self, severity: RiskLevel) -> str:
        """Get business impact based on severity"""
        impacts = {
            RiskLevel.CRITICAL: "Critical vulnerabilities could lead to complete system compromise, data breach, or service disruption with immediate business impact.",
            RiskLevel.HIGH: "High severity issues pose significant risk of unauthorized access, data exposure, or system compromise.",
            RiskLevel.MEDIUM: "Medium severity findings could be exploited under certain conditions, potentially leading to unauthorized access or information disclosure.",
            RiskLevel.LOW: "Low severity issues present minimal immediate risk but should be addressed as part of security hygiene."
        }
        return impacts.get(severity, "Security issue requires evaluation and remediation.")
