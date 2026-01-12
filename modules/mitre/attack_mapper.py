"""
MITRE ATT&CK Mapper Module
Maps findings to MITRE ATT&CK tactics and techniques
"""
from typing import List
from core.logger import Logger
from core.config import get_config
from core.models import MitreTechnique, Vulnerability


class MITREMapper:
    """Map security findings to MITRE ATT&CK framework"""
    
    # MITRE ATT&CK technique mappings
    TECHNIQUE_DATABASE = {
        # Reconnaissance
        'subdomain_discovery': {
            'id': 'T1590.002',
            'name': 'DNS/Passive DNS',
            'tactic': 'Reconnaissance',
            'description': 'Adversaries may search DNS data to gather actionable information.'
        },
        'port_scan': {
            'id': 'T1046',
            'name': 'Network Service Discovery',
            'tactic': 'Discovery',
            'description': 'Adversaries may attempt to get a listing of services running on remote hosts.'
        },
        
        # Initial Access
        'exposed_rdp': {
            'id': 'T1021.001',
            'name': 'Remote Desktop Protocol',
            'tactic': 'Lateral Movement',
            'description': 'Adversaries may use Valid Accounts to log into a computer using RDP.'
        },
        'exposed_ssh': {
            'id': 'T1021.004',
            'name': 'SSH',
            'tactic': 'Lateral Movement',
            'description': 'Adversaries may use SSH to log into remote systems.'
        },
        'exposed_smb': {
            'id': 'T1021.002',
            'name': 'SMB/Windows Admin Shares',
            'tactic': 'Lateral Movement',
            'description': 'Adversaries may use SMB to interact with remote systems.'
        },
        'web_application': {
            'id': 'T1190',
            'name': 'Exploit Public-Facing Application',
            'tactic': 'Initial Access',
            'description': 'Adversaries may exploit web application vulnerabilities to gain initial access.'
        },
        
        # Credential Access
        'telnet': {
            'id': 'T1040',
            'name': 'Network Sniffing',
            'tactic': 'Credential Access',
            'description': 'Cleartext protocols like Telnet allow credential capture through sniffing.'
        },
        'ftp': {
            'id': 'T1040',
            'name': 'Network Sniffing',
            'tactic': 'Credential Access',
            'description': 'FTP credentials can be captured through network sniffing.'
        },
        'brute_force': {
            'id': 'T1110',
            'name': 'Brute Force',
            'tactic': 'Credential Access',
            'description': 'Adversaries may use brute force techniques to gain access.'
        },
        
        # Defense Evasion
        'weak_ssl': {
            'id': 'T1557.002',
            'name': 'Man-in-the-Middle',
            'tactic': 'Defense Evasion',
            'description': 'Weak SSL/TLS enables man-in-the-middle attacks.'
        },
        
        # Collection
        'exposed_database': {
            'id': 'T1005',
            'name': 'Data from Local System',
            'tactic': 'Collection',
            'description': 'Exposed databases allow adversaries to collect sensitive data.'
        },
        
        # Exfiltration
        'unencrypted_protocol': {
            'id': 'T1048.003',
            'name': 'Exfiltration Over Unencrypted Protocol',
            'tactic': 'Exfiltration',
            'description': 'Unencrypted protocols can be used for data exfiltration.'
        },
        
        # Impact
        'dos_vulnerability': {
            'id': 'T1499',
            'name': 'Endpoint Denial of Service',
            'tactic': 'Impact',
            'description': 'Vulnerabilities can be exploited for denial of service.'
        }
    }
    
    def __init__(self):
        """Initialize MITRE mapper"""
        self.logger = Logger.get(__name__)
        self.config = get_config()
        self.enable_mapping = self.config.get('mitre.enable_mapping', True)
    
    def map_vulnerability(self, vulnerability: Vulnerability) -> List[MitreTechnique]:
        """
        Map vulnerability to MITRE ATT&CK techniques
        
        Args:
            vulnerability: Vulnerability object
            
        Returns:
            List of applicable MITRE techniques
        """
        if not self.enable_mapping:
            return []
        
        techniques = []
        
        # Map based on vulnerability characteristics
        vuln_lower = vulnerability.title.lower()
        
        # Check for specific mappings
        if 'rdp' in vuln_lower:
            techniques.append(self._create_technique('exposed_rdp'))
        
        if 'ssh' in vuln_lower:
            techniques.append(self._create_technique('exposed_ssh'))
        
        if 'smb' in vuln_lower:
            techniques.append(self._create_technique('exposed_smb'))
        
        if 'telnet' in vuln_lower:
            techniques.append(self._create_technique('telnet'))
        
        if 'ftp' in vuln_lower:
            techniques.append(self._create_technique('ftp'))
        
        if 'ssl' in vuln_lower or 'tls' in vuln_lower:
            techniques.append(self._create_technique('weak_ssl'))
        
        if any(db in vuln_lower for db in ['mysql', 'postgresql', 'mongodb', 'database']):
            techniques.append(self._create_technique('exposed_database'))
        
        if 'http' in vuln_lower and 'web' in vuln_lower:
            techniques.append(self._create_technique('web_application'))
        
        # Generic mapping for CVEs
        if vulnerability.cve_id:
            # Most CVEs can be exploited for initial access
            if not techniques:  # Only add if no specific techniques found
                techniques.append(self._create_technique('web_application'))
        
        return techniques
    
    def map_service(self, service_name: str, port: int) -> List[MitreTechnique]:
        """
        Map exposed service to MITRE ATT&CK techniques
        
        Args:
            service_name: Name of the service
            port: Port number
            
        Returns:
            List of applicable MITRE techniques
        """
        techniques = []
        
        service_mappings = {
            'rdp': 'exposed_rdp',
            'ssh': 'exposed_ssh',
            'smb': 'exposed_smb',
            'telnet': 'telnet',
            'ftp': 'ftp',
            'http': 'web_application',
            'https': 'web_application',
            'mysql': 'exposed_database',
            'postgresql': 'exposed_database',
            'mongodb': 'exposed_database'
        }
        
        if service_name.lower() in service_mappings:
            technique_key = service_mappings[service_name.lower()]
            techniques.append(self._create_technique(technique_key))
        
        # All exposed services can be discovered
        techniques.append(self._create_technique('port_scan'))
        
        return techniques
    
    def map_finding_category(self, category: str) -> List[MitreTechnique]:
        """
        Map finding category to MITRE techniques
        
        Args:
            category: Finding category
            
        Returns:
            List of techniques
        """
        techniques = []
        
        # Map based on category
        if 'recon' in category.lower():
            techniques.append(self._create_technique('subdomain_discovery'))
            techniques.append(self._create_technique('port_scan'))
        
        return techniques
    
    def _create_technique(self, key: str) -> MitreTechnique:
        """Create MitreTechnique from database"""
        if key in self.TECHNIQUE_DATABASE:
            data = self.TECHNIQUE_DATABASE[key]
            return MitreTechnique(
                technique_id=data['id'],
                name=data['name'],
                tactic=data['tactic'],
                description=data['description'],
                url=f"https://attack.mitre.org/techniques/{data['id'].replace('.', '/')}/"
            )
        
        # Return generic technique if not found
        return MitreTechnique(
            technique_id='T1078',
            name='Valid Accounts',
            tactic='Initial Access',
            description='Adversaries may obtain valid credentials for exposed services.',
            url='https://attack.mitre.org/techniques/T1078/'
        )
    
    def get_all_techniques_for_session(self, findings: list) -> List[MitreTechnique]:
        """
        Get all unique MITRE techniques from findings
        
        Args:
            findings: List of findings
            
        Returns:
            List of unique techniques
        """
        techniques_dict = {}
        
        for finding in findings:
            for technique in finding.mitre_techniques:
                if technique.technique_id not in techniques_dict:
                    techniques_dict[technique.technique_id] = technique
        
        return list(techniques_dict.values())
    
    def get_tactics_summary(self, techniques: List[MitreTechnique]) -> dict:
        """
        Get summary of tactics from techniques
        
        Args:
            techniques: List of techniques
            
        Returns:
            Dict mapping tactics to technique counts
        """
        tactics = {}
        
        for technique in techniques:
            tactic = technique.tactic
            if tactic not in tactics:
                tactics[tactic] = 0
            tactics[tactic] += 1
        
        return tactics
