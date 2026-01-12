"""
Risk Analyzer Module
Performs risk analysis and scoring on findings
"""
from core.logger import Logger
from core.config import get_config
from core.models import Finding, RiskLevel


class RiskAnalyzer:
    """Analyze and score security findings"""
    
    def __init__(self):
        """Initialize risk analyzer"""
        self.logger = Logger.get(__name__)
        self.config = get_config()
    
    def analyze_finding(self, finding: Finding):
        """
        Analyze and enhance a finding with risk information
        
        Args:
            finding: Finding to analyze (modified in place)
        """
        # If CVSS score exists, use it to determine severity
        if finding.cvss_score > 0:
            finding.severity = self._cvss_to_severity(finding.cvss_score)
        
        # Add business impact if missing
        if not finding.business_impact:
            finding.business_impact = self._generate_business_impact(finding)
        
        # Add remediation guidance if missing
        if not finding.remediation:
            finding.remediation = self._generate_remediation(finding)
    
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
    
    def _generate_business_impact(self, finding: Finding) -> str:
        """Generate business impact statement"""
        severity_impacts = {
            RiskLevel.CRITICAL: "Critical security issue that could lead to complete system compromise, "
                              "major data breach, or significant service disruption with immediate and severe business impact.",
            RiskLevel.HIGH: "High-severity security issue that poses significant risk of unauthorized access, "
                          "data exposure, or system compromise with serious business consequences.",
            RiskLevel.MEDIUM: "Medium-severity issue that could be exploited under certain conditions, "
                            "potentially leading to unauthorized access or information disclosure.",
            RiskLevel.LOW: "Low-severity issue that presents minimal immediate risk but should be addressed "
                         "as part of security hygiene and defense-in-depth strategy.",
            RiskLevel.INFO: "Informational finding that aids in understanding the attack surface and security posture."
        }
        
        return severity_impacts.get(finding.severity, "Security issue requires evaluation and remediation.")
    
    def _generate_remediation(self, finding: Finding) -> str:
        """Generate remediation guidance"""
        # Generic remediation based on category
        from core.models import FindingCategory
        
        category_remediations = {
            FindingCategory.VULNERABILITY: "Apply security patches and updates. Follow vendor security advisories.",
            FindingCategory.MISCONFIGURATION: "Review and correct configuration according to security best practices.",
            FindingCategory.EXPOSURE: "Restrict access using firewall rules, network segmentation, or authentication.",
            FindingCategory.WEAK_SECURITY: "Implement stronger security controls and follow industry standards.",
            FindingCategory.RECON: "Review information disclosure and implement appropriate access controls."
        }
        
        return category_remediations.get(finding.category, 
                                        "Consult with security team for appropriate remediation steps.")
    
    def calculate_overall_risk(self, findings: list) -> dict:
        """
        Calculate overall risk metrics
        
        Args:
            findings: List of findings
            
        Returns:
            Dict with risk metrics
        """
        total = len(findings)
        
        if total == 0:
            return {
                'total_findings': 0,
                'risk_score': 0,
                'risk_level': 'None',
                'summary': 'No security findings identified'
            }
        
        # Count by severity
        critical = len([f for f in findings if f.severity == RiskLevel.CRITICAL])
        high = len([f for f in findings if f.severity == RiskLevel.HIGH])
        medium = len([f for f in findings if f.severity == RiskLevel.MEDIUM])
        low = len([f for f in findings if f.severity == RiskLevel.LOW])
        
        # Calculate risk score (weighted)
        risk_score = (critical * 10) + (high * 7) + (medium * 4) + (low * 1)
        
        # Determine overall risk level
        if critical > 0:
            risk_level = 'Critical'
        elif high > 3:
            risk_level = 'High'
        elif high > 0 or medium > 5:
            risk_level = 'Medium'
        else:
            risk_level = 'Low'
        
        return {
            'total_findings': total,
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'summary': self._generate_risk_summary(critical, high, medium, low)
        }
    
    def _generate_risk_summary(self, critical: int, high: int, medium: int, low: int) -> str:
        """Generate risk summary statement"""
        if critical > 0:
            return (f"CRITICAL RISK: {critical} critical vulnerabilities identified requiring immediate attention. "
                   f"System is at high risk of compromise.")
        elif high > 3:
            return (f"HIGH RISK: {high} high-severity issues identified. "
                   f"Prompt remediation recommended to reduce risk of security incident.")
        elif high > 0:
            return (f"ELEVATED RISK: {high} high and {medium} medium severity issues found. "
                   f"Remediation should be prioritized.")
        elif medium > 0:
            return (f"MODERATE RISK: {medium} medium severity issues identified. "
                   f"Standard remediation procedures should be followed.")
        else:
            return f"LOW RISK: Only {low} low-severity issues found. Maintain current security posture."
