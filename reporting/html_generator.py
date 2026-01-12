"""
HTML Report Generator
Generates professional HTML reports for Red Team assessments
"""
import os
import json
from datetime import datetime
from pathlib import Path
from jinja2 import Template
from core.logger import Logger
from core.config import get_config
from core.models import ScanSession, RiskLevel
from modules.mitre.attack_mapper import MITREMapper


class HTMLReportGenerator:
    """Generate HTML reports from scan sessions"""
    
    HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Red Team Assessment Report - {{ session.target.identifier }}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px;
            margin-bottom: 30px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .section {
            background: white;
            padding: 30px;
            margin-bottom: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .section h2 {
            color: #1e3c72;
            border-bottom: 3px solid #2a5298;
            padding-bottom: 10px;
            margin-bottom: 20px;
            font-size: 1.8em;
        }
        
        .section h3 {
            color: #2a5298;
            margin-top: 20px;
            margin-bottom: 10px;
            font-size: 1.3em;
        }
        
        .executive-summary {
            background: #fff9e6;
            border-left: 5px solid #ffa500;
            padding: 20px;
            margin-bottom: 20px;
        }
        
        .risk-dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .risk-card {
            padding: 20px;
            border-radius: 8px;
            color: white;
            text-align: center;
        }
        
        .risk-card.critical {
            background: linear-gradient(135deg, #d32f2f 0%, #b71c1c 100%);
        }
        
        .risk-card.high {
            background: linear-gradient(135deg, #f57c00 0%, #e65100 100%);
        }
        
        .risk-card.medium {
            background: linear-gradient(135deg, #ffa726 0%, #fb8c00 100%);
        }
        
        .risk-card.low {
            background: linear-gradient(135deg, #66bb6a 0%, #43a047 100%);
        }
        
        .risk-card .number {
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .risk-card .label {
            font-size: 1.1em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .finding {
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            background: #fafafa;
        }
        
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .finding-title {
            font-size: 1.3em;
            font-weight: bold;
            color: #333;
        }
        
        .severity-badge {
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.9em;
        }
        
        .severity-badge.critical {
            background: #d32f2f;
            color: white;
        }
        
        .severity-badge.high {
            background: #f57c00;
            color: white;
        }
        
        .severity-badge.medium {
            background: #ffa726;
            color: white;
        }
        
        .severity-badge.low {
            background: #66bb6a;
            color: white;
        }
        
        .severity-badge.info {
            background: #42a5f5;
            color: white;
        }
        
        .finding-detail {
            margin-bottom: 15px;
        }
        
        .finding-detail strong {
            display: inline-block;
            min-width: 150px;
            color: #2a5298;
        }
        
        .code-block {
            background: #f5f5f5;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 15px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            margin: 10px 0;
        }
        
        .mitre-technique {
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
            padding: 10px;
            margin: 5px 0;
            border-radius: 4px;
        }
        
        .mitre-technique strong {
            color: #1976d2;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        
        th {
            background: #2a5298;
            color: white;
            font-weight: bold;
        }
        
        tr:hover {
            background: #f5f5f5;
        }
        
        .disclaimer {
            background: #fff3cd;
            border: 2px solid #ffc107;
            border-radius: 8px;
            padding: 20px;
            margin-top: 30px;
        }
        
        .disclaimer h3 {
            color: #856404;
            margin-bottom: 10px;
        }
        
        .footer {
            text-align: center;
            padding: 30px;
            color: #666;
            margin-top: 30px;
        }
        
        @media print {
            .container {
                max-width: 100%;
            }
            
            .section {
                page-break-inside: avoid;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Red Team Security Assessment Report</h1>
            <div class="subtitle">Target: {{ session.target.identifier }}</div>
            <div class="subtitle">Assessment Date: {{ report_date }}</div>
            <div class="subtitle">Session ID: {{ session.session_id }}</div>
        </div>
        
        <!-- Executive Summary -->
        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div class="executive-summary">
                <p><strong>Assessment Overview:</strong> This report presents the findings from a comprehensive Red Team security assessment conducted on {{ session.target.identifier }}. The assessment followed the Red Team Kill Chain methodology, encompassing Reconnaissance, Scanning, Enumeration, Vulnerability Mapping, and Risk Analysis.</p>
                
                <p style="margin-top: 15px;"><strong>Key Findings:</strong> The assessment identified <strong>{{ summary.total_findings }} security findings</strong>, including {{ summary.critical }} Critical, {{ summary.high }} High, {{ summary.medium }} Medium, and {{ summary.low }} Low severity issues.</p>
                
                <p style="margin-top: 15px;"><strong>Overall Risk Level:</strong> <span style="color: {% if summary.risk_level == 'Critical' %}#d32f2f{% elif summary.risk_level == 'High' %}#f57c00{% elif summary.risk_level == 'Medium' %}#ffa726{% else %}#66bb6a{% endif %}; font-weight: bold; font-size: 1.2em;">{{ summary.risk_level }}</span></p>
                
                <p style="margin-top: 15px;">{{ summary.summary }}</p>
            </div>
            
            <div class="risk-dashboard">
                <div class="risk-card critical">
                    <div class="number">{{ summary.critical }}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="risk-card high">
                    <div class="number">{{ summary.high }}</div>
                    <div class="label">High</div>
                </div>
                <div class="risk-card medium">
                    <div class="number">{{ summary.medium }}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="risk-card low">
                    <div class="number">{{ summary.low }}</div>
                    <div class="label">Low</div>
                </div>
            </div>
        </div>
        
        <!-- Assessment Scope -->
        <div class="section">
            <h2>🎯 Assessment Scope & Methodology</h2>
            
            <h3>Target Information</h3>
            <table>
                <tr>
                    <th>Property</th>
                    <th>Value</th>
                </tr>
                <tr>
                    <td>Target Identifier</td>
                    <td>{{ session.target.identifier }}</td>
                </tr>
                <tr>
                    <td>Target Type</td>
                    <td>{{ session.target.type }}</td>
                </tr>
                <tr>
                    <td>Assessment Duration</td>
                    <td>{{ "%.2f"|format(session.duration) }} seconds</td>
                </tr>
                <tr>
                    <td>Start Time</td>
                    <td>{{ session.start_time }}</td>
                </tr>
                <tr>
                    <td>End Time</td>
                    <td>{{ session.end_time }}</td>
                </tr>
            </table>
            
            <h3>Methodology</h3>
            <p>This assessment followed the Red Team Kill Chain methodology:</p>
            <ol>
                <li><strong>Reconnaissance:</strong> DNS enumeration, subdomain discovery, and passive information gathering</li>
                <li><strong>Scanning:</strong> Port scanning, service detection, and version identification</li>
                <li><strong>Enumeration:</strong> Web technology fingerprinting, directory discovery, and configuration analysis</li>
                <li><strong>Vulnerability Mapping:</strong> CVE identification, misconfiguration detection, and weakness analysis</li>
                <li><strong>Risk Analysis:</strong> CVSS scoring, business impact assessment, and prioritization</li>
            </ol>
            
            <p style="margin-top: 15px;"><strong>Important:</strong> This assessment focuses on proof-of-exposure, not exploitation. No destructive actions were performed.</p>
        </div>
        
        <!-- Attack Surface Overview -->
        {% if session.scan_results %}
        <div class="section">
            <h2>🌐 Attack Surface Overview</h2>
            
            <h3>Exposed Services</h3>
            <p>The following services were discovered as exposed on the target:</p>
            
            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>State</th>
                        <th>Service</th>
                        <th>Version</th>
                    </tr>
                </thead>
                <tbody>
                {% for port in session.scan_results.ports %}
                    {% if port.state == 'open' %}
                    <tr>
                        <td>{{ port.number }}</td>
                        <td>{{ port.protocol.upper() }}</td>
                        <td>{{ port.state }}</td>
                        <td>{{ port.service or 'Unknown' }}</td>
                        <td>{{ port.version or 'N/A' }}</td>
                    </tr>
                    {% endif %}
                {% endfor %}
                </tbody>
            </table>
            
            {% if session.scan_results.os_detection %}
            <h3>Operating System Detection</h3>
            <div class="code-block">
                OS: {{ session.scan_results.os_detection.get('name', 'Unknown') }}<br>
                Accuracy: {{ session.scan_results.os_detection.get('accuracy', 'N/A') }}%
            </div>
            {% endif %}
        </div>
        {% endif %}
        
        <!-- Detailed Findings -->
        <div class="section">
            <h2>🔍 Detailed Security Findings</h2>
            
            {% if session.findings %}
                {% for finding in session.findings %}
                <div class="finding">
                    <div class="finding-header">
                        <div class="finding-title">{{ finding.id }}: {{ finding.title }}</div>
                        <div class="severity-badge {{ finding.severity.value.lower() }}">
                            {{ finding.severity.value }}
                        </div>
                    </div>
                    
                    <div class="finding-detail">
                        <strong>Category:</strong> {{ finding.category.value }}
                    </div>
                    
                    <div class="finding-detail">
                        <strong>Description:</strong><br>
                        {{ finding.description }}
                    </div>
                    
                    <div class="finding-detail">
                        <strong>Affected Target:</strong> {{ finding.affected_target }}
                    </div>
                    
                    {% if finding.affected_component %}
                    <div class="finding-detail">
                        <strong>Affected Component:</strong> {{ finding.affected_component }}
                    </div>
                    {% endif %}
                    
                    {% if finding.proof_of_exposure %}
                    <div class="finding-detail">
                        <strong>Proof of Exposure:</strong>
                        <div class="code-block">{{ finding.proof_of_exposure }}</div>
                    </div>
                    {% endif %}
                    
                    {% if finding.cvss_score > 0 %}
                    <div class="finding-detail">
                        <strong>CVSS Score:</strong> {{ "%.1f"|format(finding.cvss_score) }} / 10.0
                    </div>
                    {% endif %}
                    
                    {% if finding.cve_ids %}
                    <div class="finding-detail">
                        <strong>CVE IDs:</strong> {{ finding.cve_ids | join(', ') }}
                    </div>
                    {% endif %}
                    
                    <div class="finding-detail">
                        <strong>Business Impact:</strong><br>
                        {{ finding.business_impact }}
                    </div>
                    
                    {% if finding.mitre_techniques %}
                    <div class="finding-detail">
                        <strong>MITRE ATT&CK Mapping:</strong>
                        {% for technique in finding.mitre_techniques %}
                        <div class="mitre-technique">
                            <strong>{{ technique.technique_id }}</strong> - {{ technique.name }}<br>
                            <em>Tactic:</em> {{ technique.tactic }}<br>
                            {{ technique.description }}
                        </div>
                        {% endfor %}
                    </div>
                    {% endif %}
                    
                    <div class="finding-detail">
                        <strong>Remediation:</strong><br>
                        {{ finding.remediation }}
                    </div>
                    
                    {% if finding.references %}
                    <div class="finding-detail">
                        <strong>References:</strong>
                        <ul>
                        {% for ref in finding.references %}
                            <li><a href="{{ ref }}" target="_blank">{{ ref }}</a></li>
                        {% endfor %}
                        </ul>
                    </div>
                    {% endif %}
                </div>
                {% endfor %}
            {% else %}
                <p>No security findings were identified during this assessment.</p>
            {% endif %}
        </div>
        
        <!-- MITRE ATT&CK Overview -->
        {% if mitre_techniques %}
        <div class="section">
            <h2>⚔️ MITRE ATT&CK Framework Mapping</h2>
            
            <p>The following MITRE ATT&CK techniques are applicable based on the discovered vulnerabilities and exposures:</p>
            
            <table>
                <thead>
                    <tr>
                        <th>Technique ID</th>
                        <th>Technique Name</th>
                        <th>Tactic</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                {% for technique in mitre_techniques %}
                    <tr>
                        <td><a href="{{ technique.url }}" target="_blank">{{ technique.technique_id }}</a></td>
                        <td>{{ technique.name }}</td>
                        <td>{{ technique.tactic }}</td>
                        <td>{{ technique.description[:100] }}...</td>
                    </tr>
                {% endfor %}
                </tbody>
            </table>
            
            <h3>Tactics Summary</h3>
            <div class="risk-dashboard">
                {% for tactic, count in tactics_summary.items() %}
                <div class="risk-card low">
                    <div class="number">{{ count }}</div>
                    <div class="label">{{ tactic }}</div>
                </div>
                {% endfor %}
            </div>
        </div>
        {% endif %}
        
        <!-- Recommendations -->
        <div class="section">
            <h2>💡 Recommendations</h2>
            
            <h3>Immediate Actions (Critical & High Priority)</h3>
            <ol>
                {% if summary.critical > 0 %}
                <li>Address all {{ summary.critical }} critical vulnerabilities immediately</li>
                {% endif %}
                {% if summary.high > 0 %}
                <li>Remediate {{ summary.high }} high-severity findings within 30 days</li>
                {% endif %}
                <li>Implement network segmentation to reduce attack surface</li>
                <li>Deploy intrusion detection/prevention systems (IDS/IPS)</li>
                <li>Enable comprehensive security logging and monitoring</li>
            </ol>
            
            <h3>Medium-Term Actions</h3>
            <ol>
                <li>Develop and test incident response procedures</li>
                <li>Conduct regular security awareness training</li>
                <li>Implement vulnerability management program</li>
                <li>Perform regular penetration testing and security assessments</li>
                <li>Review and harden system configurations</li>
            </ol>
            
            <h3>Long-Term Strategy</h3>
            <ol>
                <li>Establish security governance framework</li>
                <li>Implement Defense-in-Depth security architecture</li>
                <li>Develop threat intelligence capabilities</li>
                <li>Regular Red Team exercises for continuous improvement</li>
                <li>Foster security-first culture across organization</li>
            </ol>
        </div>
        
        <!-- Disclaimer -->
        <div class="disclaimer">
            <h3>⚠️ Important Disclaimer</h3>
            <p><strong>Authorized Use Only:</strong> This assessment was conducted with proper authorization for educational and security improvement purposes only.</p>
            
            <p><strong>No Exploitation:</strong> This assessment focused on identifying exposures and vulnerabilities without performing actual exploitation or causing system disruption.</p>
            
            <p><strong>Scope Limitation:</strong> Findings are limited to the assessed target and methodology employed. Additional vulnerabilities may exist outside the assessment scope.</p>
            
            <p><strong>Remediation:</strong> Organizations should prioritize remediation based on their specific risk tolerance, business requirements, and operational constraints.</p>
            
            <p><strong>Confidentiality:</strong> This report contains sensitive security information and should be handled according to organizational data classification policies.</p>
        </div>
        
        <div class="footer">
            <p>Report generated by Red Team Automation Framework v1.0.0</p>
            <p>Generated on: {{ report_date }}</p>
            <p><em>For authorized security testing and educational purposes only</em></p>
        </div>
    </div>
</body>
</html>
"""
    
    def __init__(self):
        """Initialize HTML report generator"""
        self.logger = Logger.get(__name__)
        self.config = get_config()
        self.output_dir = self.config.get('reporting.output_dir', 'reports')
        
        # Create output directory
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
    
    def generate(self, session: ScanSession) -> str:
        """
        Generate HTML report from scan session
        
        Args:
            session: ScanSession with assessment results
            
        Returns:
            Path to generated HTML report
        """
        self.logger.info("Generating HTML report...")
        
        # Prepare data for template
        from modules.vuln.risk_analyzer import RiskAnalyzer
        analyzer = RiskAnalyzer()
        summary = analyzer.calculate_overall_risk(session.findings)
        
        # Get MITRE techniques
        mitre_mapper = MITREMapper()
        mitre_techniques = mitre_mapper.get_all_techniques_for_session(session.findings)
        tactics_summary = mitre_mapper.get_tactics_summary(mitre_techniques)
        
        # Render template
        template = Template(self.HTML_TEMPLATE)
        html_content = template.render(
            session=session,
            summary=summary,
            report_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            mitre_techniques=mitre_techniques,
            tactics_summary=tactics_summary
        )
        
        # Write to file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"redteam_report_{session.target.identifier.replace('/', '_')}_{timestamp}.html"
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.info(f"HTML report generated: {filepath}")
        
        return filepath
    
    def generate_json(self, session: ScanSession) -> str:
        """
        Generate JSON report from scan session
        
        Args:
            session: ScanSession with assessment results
            
        Returns:
            Path to generated JSON report
        """
        self.logger.info("Generating JSON report...")
        
        # Convert session to dict
        report_data = {
            'session_id': session.session_id,
            'target': {
                'identifier': session.target.identifier,
                'type': session.target.type,
                'ip_addresses': session.target.ip_addresses,
                'domains': session.target.domains
            },
            'start_time': session.start_time.isoformat(),
            'end_time': session.end_time.isoformat() if session.end_time else None,
            'duration': session.duration,
            'findings': [
                {
                    'id': f.id,
                    'title': f.title,
                    'category': f.category.value,
                    'severity': f.severity.value,
                    'description': f.description,
                    'affected_target': f.affected_target,
                    'affected_component': f.affected_component,
                    'proof_of_exposure': f.proof_of_exposure,
                    'business_impact': f.business_impact,
                    'cvss_score': f.cvss_score,
                    'cve_ids': f.cve_ids,
                    'remediation': f.remediation,
                    'references': f.references,
                    'mitre_techniques': [
                        {
                            'technique_id': t.technique_id,
                            'name': t.name,
                            'tactic': t.tactic,
                            'description': t.description,
                            'url': t.url
                        }
                        for t in f.mitre_techniques
                    ]
                }
                for f in session.findings
            ],
            'risk_summary': session.get_risk_summary()
        }
        
        # Write to file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"redteam_report_{session.target.identifier.replace('/', '_')}_{timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)
        
        self.logger.info(f"JSON report generated: {filepath}")
        
        return filepath
