"""
CVE Mapper Module
Maps discovered services to known CVEs
"""
import re
import requests
from typing import List
from core.logger import Logger
from core.config import get_config
from core.models import Vulnerability, RiskLevel


class CVEMapper:
    """Map services and versions to known CVEs"""
    
    # Known vulnerable versions (simplified database)
    KNOWN_VULNERABILITIES = {
        'apache': {
            '2.4.49': {
                'cve': 'CVE-2021-41773',
                'title': 'Apache HTTP Server 2.4.49 Path Traversal',
                'cvss': 7.5,
                'description': 'Path traversal and remote code execution vulnerability',
                'remediation': 'Upgrade to Apache 2.4.51 or later'
            },
            '2.4.50': {
                'cve': 'CVE-2021-42013',
                'title': 'Apache HTTP Server 2.4.50 Path Traversal',
                'cvss': 9.8,
                'description': 'Path traversal and remote code execution vulnerability',
                'remediation': 'Upgrade to Apache 2.4.51 or later'
            }
        },
        'nginx': {
            '1.20.0': {
                'cve': 'CVE-2021-23017',
                'title': 'Nginx DNS Resolver Off-by-One Heap Write',
                'cvss': 9.8,
                'description': 'Off-by-one heap write in DNS resolver',
                'remediation': 'Upgrade to Nginx 1.20.1 or later'
            }
        },
        'openssh': {
            '7.4': {
                'cve': 'CVE-2018-15473',
                'title': 'OpenSSH User Enumeration',
                'cvss': 5.3,
                'description': 'Username enumeration via timing attack',
                'remediation': 'Upgrade to OpenSSH 7.8 or later'
            }
        },
        'mysql': {
            '5.7.0': {
                'cve': 'CVE-2021-2166',
                'title': 'MySQL Server Vulnerability',
                'cvss': 4.9,
                'description': 'Denial of service vulnerability',
                'remediation': 'Upgrade to MySQL 5.7.34 or later'
            }
        },
        'wordpress': {
            '5.7.0': {
                'cve': 'CVE-2021-29447',
                'title': 'WordPress XXE Vulnerability',
                'cvss': 7.5,
                'description': 'XXE vulnerability in Media Library',
                'remediation': 'Upgrade to WordPress 5.7.1 or later'
            }
        }
    }
    
    def __init__(self):
        """Initialize CVE mapper"""
        self.logger = Logger.get(__name__)
        self.config = get_config()
        self.enable_api = self.config.get('vulnerability.enable_cve_lookup', True)
        self.timeout = self.config.get('vulnerability.cve_api_timeout', 10)
    
    def check_service(self, service: str, version: str) -> List[Vulnerability]:
        """
        Check if service/version has known vulnerabilities
        
        Args:
            service: Service name (e.g., 'apache', 'nginx')
            version: Version string
            
        Returns:
            List of vulnerabilities
        """
        if not service or not version:
            return []
        
        self.logger.debug(f"Checking CVEs for {service} {version}")
        
        vulnerabilities = []
        
        # Check local vulnerability database
        service_lower = service.lower()
        if service_lower in self.KNOWN_VULNERABILITIES:
            # Extract version number (simplified)
            version_clean = self._clean_version(version)
            
            if version_clean in self.KNOWN_VULNERABILITIES[service_lower]:
                vuln_data = self.KNOWN_VULNERABILITIES[service_lower][version_clean]
                
                vuln = Vulnerability(
                    title=vuln_data['title'],
                    description=vuln_data['description'],
                    cve_id=vuln_data['cve'],
                    cvss_score=vuln_data['cvss'],
                    severity=self._cvss_to_severity(vuln_data['cvss']),
                    affected_component=f"{service} {version}",
                    proof_of_exposure=f"Service {service} version {version} is known to be vulnerable",
                    remediation=vuln_data['remediation'],
                    references=[f"https://nvd.nist.gov/vuln/detail/{vuln_data['cve']}"]
                )
                vulnerabilities.append(vuln)
                self.logger.info(f"Found CVE: {vuln_data['cve']} for {service} {version}")
        
        # Check for generic service vulnerabilities
        generic_vulns = self._check_generic_vulnerabilities(service, version)
        vulnerabilities.extend(generic_vulns)
        
        return vulnerabilities
    
    def _clean_version(self, version: str) -> str:
        """Extract clean version number"""
        # Extract version pattern like X.Y.Z
        match = re.search(r'(\d+\.\d+\.?\d*)', version)
        if match:
            return match.group(1)
        return version
    
    def _cvss_to_severity(self, cvss: float) -> RiskLevel:
        """Convert CVSS score to severity level"""
        critical_threshold = self.config.get('risk.critical_threshold', 9.0)
        high_threshold = self.config.get('risk.high_threshold', 7.0)
        medium_threshold = self.config.get('risk.medium_threshold', 4.0)
        
        if cvss >= critical_threshold:
            return RiskLevel.CRITICAL
        elif cvss >= high_threshold:
            return RiskLevel.HIGH
        elif cvss >= medium_threshold:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _check_generic_vulnerabilities(self, service: str, version: str) -> List[Vulnerability]:
        """Check for generic service vulnerabilities"""
        vulnerabilities = []
        
        # Check for outdated/insecure services
        insecure_services = {
            'telnet': {
                'title': 'Insecure Protocol: Telnet',
                'description': 'Telnet transmits data including credentials in cleartext',
                'cvss': 7.5,
                'remediation': 'Disable Telnet and use SSH instead'
            },
            'ftp': {
                'title': 'Insecure Protocol: FTP',
                'description': 'FTP transmits credentials in cleartext. Consider SFTP or FTPS.',
                'cvss': 6.5,
                'remediation': 'Use SFTP or FTPS instead of plain FTP'
            },
            'http': {
                'title': 'Unencrypted HTTP',
                'description': 'HTTP transmits data without encryption',
                'cvss': 5.0,
                'remediation': 'Implement HTTPS with valid SSL/TLS certificate'
            }
        }
        
        service_lower = service.lower()
        if service_lower in insecure_services:
            vuln_data = insecure_services[service_lower]
            
            vuln = Vulnerability(
                title=vuln_data['title'],
                description=vuln_data['description'],
                cvss_score=vuln_data['cvss'],
                severity=self._cvss_to_severity(vuln_data['cvss']),
                affected_component=f"{service} {version}",
                proof_of_exposure=f"Insecure protocol {service} is in use",
                remediation=vuln_data['remediation']
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def query_nvd_api(self, cve_id: str) -> dict:
        """
        Query NVD API for CVE details (optional)
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            CVE details dict
        """
        if not self.enable_api:
            return {}
        
        try:
            # NVD API v2
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {'cveId': cve_id}
            
            response = requests.get(url, params=params, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                return data
            else:
                self.logger.debug(f"NVD API returned status {response.status_code}")
        except Exception as e:
            self.logger.debug(f"NVD API query failed: {e}")
        
        return {}
