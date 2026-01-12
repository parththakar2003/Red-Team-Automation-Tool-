"""
Data Models for Red Team Framework
Defines structured data objects for scan results
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum


class RiskLevel(Enum):
    """Risk severity levels"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class FindingCategory(Enum):
    """Categories of security findings"""
    RECON = "Reconnaissance"
    EXPOSURE = "Exposure"
    VULNERABILITY = "Vulnerability"
    MISCONFIGURATION = "Misconfiguration"
    WEAK_SECURITY = "Weak Security Practice"


@dataclass
class Target:
    """Target information"""
    identifier: str  # IP, domain, or CIDR
    type: str  # ip, domain, cidr
    ip_addresses: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReconResult:
    """Reconnaissance findings"""
    target: str
    dns_records: Dict[str, List[str]] = field(default_factory=dict)
    subdomains: List[str] = field(default_factory=list)
    ip_addresses: List[str] = field(default_factory=list)
    whois_data: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class Port:
    """Port information"""
    number: int
    protocol: str  # tcp/udp
    state: str  # open, closed, filtered
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None


@dataclass
class ScanResult:
    """Port scanning results"""
    target: str
    ports: List[Port] = field(default_factory=list)
    os_detection: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class WebTechnology:
    """Web technology information"""
    name: str
    version: Optional[str] = None
    category: str = ""  # cms, framework, server, etc.


@dataclass
class EnumResult:
    """Enumeration results"""
    target: str
    web_technologies: List[WebTechnology] = field(default_factory=list)
    directories: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    ssl_info: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class MitreTechnique:
    """MITRE ATT&CK technique"""
    technique_id: str
    name: str
    tactic: str
    description: str
    url: str = ""


@dataclass
class Vulnerability:
    """Vulnerability information"""
    title: str
    description: str
    cve_id: Optional[str] = None
    cvss_score: float = 0.0
    severity: RiskLevel = RiskLevel.INFO
    affected_component: str = ""
    proof_of_exposure: str = ""
    mitre_techniques: List[MitreTechnique] = field(default_factory=list)
    remediation: str = ""
    references: List[str] = field(default_factory=list)


@dataclass
class Finding:
    """Security finding"""
    id: str
    title: str
    category: FindingCategory
    severity: RiskLevel
    description: str
    affected_target: str
    affected_component: str = ""
    proof_of_exposure: str = ""
    business_impact: str = ""
    cvss_score: float = 0.0
    cve_ids: List[str] = field(default_factory=list)
    mitre_techniques: List[MitreTechnique] = field(default_factory=list)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class ScanSession:
    """Complete scan session data"""
    session_id: str
    target: Target
    start_time: datetime
    end_time: Optional[datetime] = None
    recon_results: Optional[ReconResult] = None
    scan_results: Optional[ScanResult] = None
    enum_results: Optional[EnumResult] = None
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def duration(self) -> float:
        """Get scan duration in seconds"""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0
    
    def get_findings_by_severity(self, severity: RiskLevel) -> List[Finding]:
        """Get findings filtered by severity"""
        return [f for f in self.findings if f.severity == severity]
    
    def get_critical_count(self) -> int:
        """Get count of critical findings"""
        return len(self.get_findings_by_severity(RiskLevel.CRITICAL))
    
    def get_high_count(self) -> int:
        """Get count of high severity findings"""
        return len(self.get_findings_by_severity(RiskLevel.HIGH))
    
    def get_medium_count(self) -> int:
        """Get count of medium severity findings"""
        return len(self.get_findings_by_severity(RiskLevel.MEDIUM))
    
    def get_low_count(self) -> int:
        """Get count of low severity findings"""
        return len(self.get_findings_by_severity(RiskLevel.LOW))
    
    def get_risk_summary(self) -> Dict[str, int]:
        """Get summary of findings by risk level"""
        return {
            "critical": self.get_critical_count(),
            "high": self.get_high_count(),
            "medium": self.get_medium_count(),
            "low": self.get_low_count(),
            "info": len(self.get_findings_by_severity(RiskLevel.INFO))
        }
