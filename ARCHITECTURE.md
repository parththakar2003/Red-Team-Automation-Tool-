# Architecture Documentation

## Overview

The Red Team Automation Framework follows a modular, layered architecture designed for extensibility, maintainability, and professional security assessments.

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     CLI Interface (main.py)                 │
│              User Interaction & Authorization               │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   Core Orchestrator                         │
│         Coordinates Red Team Kill Chain Workflow            │
└────┬────────────────────┬────────────────────┬──────────────┘
     │                    │                    │
     ▼                    ▼                    ▼
┌────────────┐    ┌──────────────┐    ┌───────────────┐
│   Recon    │    │   Scanning   │    │  Enumeration  │
│  Modules   │───▶│   Modules    │───▶│   Modules     │
└────────────┘    └──────────────┘    └───────┬───────┘
                                               │
                                               ▼
                                      ┌────────────────┐
                                      │ Vulnerability  │
                                      │    Mapping     │
                                      └───────┬────────┘
                                              │
                                              ▼
                                      ┌───────────────┐
                                      │ Risk Analysis │
                                      │  & MITRE      │
                                      └───────┬───────┘
                                              │
                                              ▼
                                      ┌───────────────┐
                                      │   Reporting   │
                                      │  HTML / JSON  │
                                      └───────────────┘
```

## Component Layers

### 1. Presentation Layer (CLI)

**File:** `main.py`

- User interface and command-line argument parsing
- Ethical disclaimer and authorization confirmation
- Result presentation and summary display
- Error handling and user feedback

### 2. Orchestration Layer

**File:** `core/orchestrator.py`

- Coordinates all assessment phases
- Manages workflow execution
- Handles module dependencies
- Collects and aggregates results
- Implements Red Team Kill Chain methodology

**Key Methods:**
- `run_assessment()` - Main assessment workflow
- `_run_reconnaissance()` - Phase 1
- `_run_scanning()` - Phase 2
- `_run_enumeration()` - Phase 3
- `_run_vulnerability_mapping()` - Phase 4
- `_run_risk_analysis()` - Phase 5

### 3. Core Components

**Configuration Management** (`core/config.py`)
- YAML-based configuration loading
- Centralized settings access
- Environment-specific configurations

**Data Models** (`core/models.py`)
- Structured data representations
- Type safety with dataclasses
- Finding categorization and risk levels

**Logging** (`core/logger.py`)
- Centralized logging system
- File and console output
- Debug and audit trail

### 4. Module Layer

#### Reconnaissance Modules (`modules/recon/`)

**DNS Enumerator** (`dns_enum.py`)
- A, AAAA, MX, NS, TXT, SOA, CNAME records
- Reverse DNS lookups
- Zone transfer attempts (educational)

**Subdomain Discovery** (`subdomain_discovery.py`)
- Certificate transparency logs
- DNS brute forcing
- Subdomain takeover checks

#### Scanning Modules (`modules/scan/`)

**Port Scanner** (`port_scanner.py`)
- TCP/UDP port scanning via nmap
- Service version detection
- OS fingerprinting
- Banner grabbing fallback

#### Enumeration Modules (`modules/enum/`)

**Web Technology Identifier** (`web_tech.py`)
- CMS detection (WordPress, Joomla, Drupal)
- Framework identification (React, Angular, Django)
- Server fingerprinting
- SSL/TLS analysis

**Directory Enumerator** (`directory_enum.py`)
- Common path discovery
- Sensitive file detection
- Concurrent scanning
- Smart categorization

#### Vulnerability Modules (`modules/vuln/`)

**CVE Mapper** (`cve_mapper.py`)
- Known vulnerability database
- Service-to-CVE mapping
- CVSS scoring
- Insecure protocol detection

**Misconfiguration Checker** (`misconfig_checker.py`)
- Security header validation
- Exposed service detection
- SSL/TLS misconfiguration checks
- Version disclosure detection

**Risk Analyzer** (`risk_analyzer.py`)
- CVSS-based severity classification
- Business impact assessment
- Overall risk calculation
- Remediation guidance

#### MITRE ATT&CK Module (`modules/mitre/`)

**Attack Mapper** (`attack_mapper.py`)
- Technique mapping
- Tactic identification
- Kill chain correlation
- Framework integration

### 5. Reporting Layer (`reporting/`)

**HTML Report Generator** (`html_generator.py`)
- Professional CISO-ready reports
- Executive summary generation
- Risk dashboards
- Detailed findings with evidence
- MITRE ATT&CK visualization
- JSON export for automation

### 6. Utilities Layer (`utils/`)

**Banner & CLI Utilities** (`banner.py`)
- Visual interface elements
- Color-coded output
- Authorization prompts
- Disclaimer display

## Data Flow

1. **User Input** → CLI validates and parses arguments
2. **Authorization** → Ethical confirmation required
3. **Configuration** → Settings loaded from config.yaml
4. **Session Creation** → ScanSession object initialized
5. **Reconnaissance** → DNS/subdomain data collected
6. **Scanning** → Ports/services discovered
7. **Enumeration** → Web technologies identified
8. **Vulnerability Mapping** → CVEs and misconfigs found
9. **Risk Analysis** → Findings scored and prioritized
10. **Reporting** → HTML/JSON reports generated
11. **Summary** → Results displayed to user

## Design Patterns

### 1. Orchestrator Pattern
- Central coordinator manages complex workflow
- Decouples modules from each other
- Enforces execution order

### 2. Strategy Pattern
- Different scanning strategies (modules)
- Pluggable and interchangeable
- Easy to add new modules

### 3. Builder Pattern
- ScanSession builds up over phases
- Incremental data collection
- Final comprehensive result

### 4. Singleton Pattern
- Configuration manager
- Logger instances
- Shared resources

## Extension Points

### Adding New Modules

1. Create module directory under `modules/`
2. Implement module class with standard interface
3. Add to orchestrator workflow
4. Update configuration if needed
5. Document in README

### Adding New Checks

1. Add to appropriate module (vuln, misconfig)
2. Follow existing patterns
3. Include business impact
4. Map to MITRE if applicable

### Custom Report Formats

1. Create new generator in `reporting/`
2. Implement generate() method
3. Add to main.py reporting section

## Security Considerations

### Safe by Design

- No exploitation - only proof-of-exposure
- Rate limiting to prevent DoS
- Timeout protections
- Error handling prevents crashes
- User authorization required

### Data Protection

- No credential storage
- Sensitive data marked in logs
- Reports contain disclaimers
- Minimal data retention

### Extensibility

- Plugin architecture ready
- Configuration-driven behavior
- Module isolation
- Clear interfaces

## Performance Optimization

- Concurrent subdomain checking
- Threaded directory enumeration
- Connection pooling
- Smart caching where appropriate
- Configurable timeouts

## Future Architecture Enhancements

1. **Plugin System** - Dynamic module loading
2. **Database Backend** - Persistent storage for large scans
3. **API Server** - RESTful API for integration
4. **Queue System** - Async job processing
5. **Distributed Scanning** - Multi-node coordination
6. **Real-time Dashboard** - WebSocket-based UI

---

This architecture ensures the framework remains:
- **Maintainable** - Clear separation of concerns
- **Extensible** - Easy to add new features
- **Professional** - Enterprise-ready quality
- **Educational** - Clear structure for learning
