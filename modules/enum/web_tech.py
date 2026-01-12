"""
Web Technology Identification Module
Identifies web technologies, frameworks, and CMS
"""
import requests
import re
from typing import List
from bs4 import BeautifulSoup
from core.logger import Logger
from core.config import get_config
from core.models import EnumResult, WebTechnology


class WebTechIdentifier:
    """Identify web technologies and frameworks"""
    
    # Technology fingerprints
    TECH_SIGNATURES = {
        # CMS
        'WordPress': {
            'headers': ['x-powered-by'],
            'patterns': [r'/wp-content/', r'/wp-includes/', r'wp-json'],
            'meta': ['generator']
        },
        'Joomla': {
            'patterns': [r'/components/com_', r'/modules/mod_', r'Joomla!'],
            'meta': ['generator']
        },
        'Drupal': {
            'patterns': [r'/sites/all/', r'/sites/default/', r'Drupal'],
            'headers': ['x-drupal-cache', 'x-generator']
        },
        'Magento': {
            'patterns': [r'/skin/frontend/', r'/media/catalog/', r'Mage.Cookies'],
        },
        # Frameworks
        'React': {
            'patterns': [r'react', r'_reactRoot', r'data-react']
        },
        'Angular': {
            'patterns': [r'ng-app', r'ng-controller', r'angular.js']
        },
        'Vue.js': {
            'patterns': [r'vue.js', r'v-if', r'v-for']
        },
        'Django': {
            'headers': ['x-frame-options'],
            'patterns': [r'csrfmiddlewaretoken', r'__admin']
        },
        'Flask': {
            'headers': ['server'],
            'patterns': [r'werkzeug']
        },
        'Laravel': {
            'patterns': [r'laravel_session', r'XSRF-TOKEN']
        },
        # Web Servers
        'Apache': {
            'headers': ['server']
        },
        'Nginx': {
            'headers': ['server']
        },
        'IIS': {
            'headers': ['server', 'x-powered-by']
        },
        # Other
        'jQuery': {
            'patterns': [r'jquery', r'\$\(']
        },
        'Bootstrap': {
            'patterns': [r'bootstrap.min', r'class="[^"]*bootstrap']
        }
    }
    
    def __init__(self):
        """Initialize web tech identifier"""
        self.logger = Logger.get(__name__)
        self.config = get_config()
        self.timeout = self.config.get('scan.connection_timeout', 10)
        self.user_agent = self.config.get('scan.user_agent', 
                                         'Mozilla/5.0 Red Team Assessment Tool')
    
    def identify(self, url: str) -> EnumResult:
        """
        Identify web technologies at URL
        
        Args:
            url: Target URL to analyze
            
        Returns:
            EnumResult with identified technologies
        """
        self.logger.info(f"Identifying web technologies at {url}")
        
        result = EnumResult(target=url)
        
        try:
            # Make HTTP request
            headers = {'User-Agent': self.user_agent}
            response = requests.get(url, headers=headers, timeout=self.timeout,
                                   verify=False, allow_redirects=True)
            
            # Store response headers
            result.headers = dict(response.headers)
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Identify technologies
            technologies = self._identify_technologies(response, soup)
            result.web_technologies = technologies
            
            # Check SSL/TLS if HTTPS
            if url.startswith('https'):
                result.ssl_info = self._check_ssl(url)
            
            # Discover common endpoints
            result.endpoints = self._discover_endpoints(url)
            
            self.logger.info(f"Identified {len(technologies)} technologies")
            
        except requests.RequestException as e:
            self.logger.error(f"Failed to connect to {url}: {e}")
        except Exception as e:
            self.logger.error(f"Web tech identification failed: {e}")
        
        return result
    
    def _identify_technologies(self, response, soup) -> List[WebTechnology]:
        """Identify technologies from response and HTML"""
        technologies = []
        identified = set()
        
        content = response.text.lower()
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        for tech_name, signatures in self.TECH_SIGNATURES.items():
            if tech_name in identified:
                continue
            
            # Check headers
            if 'headers' in signatures:
                for header in signatures['headers']:
                    if header in headers:
                        header_value = headers[header]
                        if tech_name.lower() in header_value or self._check_header_match(tech_name, header_value):
                            version = self._extract_version(header_value)
                            technologies.append(WebTechnology(
                                name=tech_name,
                                version=version,
                                category=self._get_category(tech_name)
                            ))
                            identified.add(tech_name)
                            break
            
            # Check patterns in content
            if tech_name not in identified and 'patterns' in signatures:
                for pattern in signatures['patterns']:
                    if re.search(pattern, content, re.IGNORECASE):
                        # Try to extract version
                        version = self._extract_version_from_content(content, tech_name)
                        technologies.append(WebTechnology(
                            name=tech_name,
                            version=version,
                            category=self._get_category(tech_name)
                        ))
                        identified.add(tech_name)
                        break
            
            # Check meta tags
            if tech_name not in identified and 'meta' in signatures:
                for meta_name in signatures['meta']:
                    meta_tag = soup.find('meta', attrs={'name': meta_name})
                    if meta_tag and meta_tag.get('content'):
                        content_value = meta_tag['content']
                        if tech_name.lower() in content_value.lower():
                            version = self._extract_version(content_value)
                            technologies.append(WebTechnology(
                                name=tech_name,
                                version=version,
                                category=self._get_category(tech_name)
                            ))
                            identified.add(tech_name)
                            break
        
        # Check for common JavaScript libraries
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            src = script['src'].lower()
            for lib in ['jquery', 'bootstrap', 'angular', 'react', 'vue']:
                if lib in src and lib.title() not in identified:
                    version = self._extract_version(src)
                    technologies.append(WebTechnology(
                        name=lib.title(),
                        version=version,
                        category='JavaScript Library'
                    ))
                    identified.add(lib.title())
        
        return technologies
    
    def _check_header_match(self, tech_name: str, header_value: str) -> bool:
        """Check if header value matches technology"""
        tech_keywords = {
            'Apache': ['apache'],
            'Nginx': ['nginx'],
            'IIS': ['iis', 'microsoft-iis'],
            'PHP': ['php'],
            'ASP.NET': ['asp.net'],
        }
        
        keywords = tech_keywords.get(tech_name, [tech_name.lower()])
        return any(kw in header_value for kw in keywords)
    
    def _extract_version(self, text: str) -> str:
        """Extract version number from text"""
        # Look for version patterns like 1.0, 2.3.4, v1.0.0, etc.
        patterns = [
            r'v?(\d+\.\d+\.\d+)',
            r'v?(\d+\.\d+)',
            r'version[/\s]?(\d+\.\d+(?:\.\d+)?)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _extract_version_from_content(self, content: str, tech_name: str) -> str:
        """Extract version from page content"""
        # Look for version near technology name
        pattern = rf'{tech_name}[/\s]+v?(\d+\.\d+(?:\.\d+)?)'
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            return match.group(1)
        return None
    
    def _get_category(self, tech_name: str) -> str:
        """Get category for technology"""
        categories = {
            'WordPress': 'CMS', 'Joomla': 'CMS', 'Drupal': 'CMS', 'Magento': 'CMS',
            'React': 'Framework', 'Angular': 'Framework', 'Vue.js': 'Framework',
            'Django': 'Framework', 'Flask': 'Framework', 'Laravel': 'Framework',
            'Apache': 'Web Server', 'Nginx': 'Web Server', 'IIS': 'Web Server',
            'jQuery': 'Library', 'Bootstrap': 'Library'
        }
        return categories.get(tech_name, 'Unknown')
    
    def _check_ssl(self, url: str) -> dict:
        """Check SSL/TLS configuration"""
        import ssl
        import socket
        from urllib.parse import urlparse
        
        ssl_info = {}
        
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            port = parsed.port or 443
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info['version'] = ssock.version()
                    ssl_info['cipher'] = ssock.cipher()
                    ssl_info['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                    ssl_info['subject'] = dict(x[0] for x in cert.get('subject', []))
                    ssl_info['notBefore'] = cert.get('notBefore')
                    ssl_info['notAfter'] = cert.get('notAfter')
                    
                    self.logger.debug(f"SSL Version: {ssl_info['version']}")
        except Exception as e:
            self.logger.debug(f"SSL check failed: {e}")
            ssl_info['error'] = str(e)
        
        return ssl_info
    
    def _discover_endpoints(self, base_url: str) -> List[str]:
        """Discover common endpoints"""
        common_endpoints = [
            '/robots.txt', '/sitemap.xml', '/.well-known/security.txt',
            '/admin', '/login', '/wp-admin', '/api', '/.git/config'
        ]
        
        discovered = []
        
        for endpoint in common_endpoints:
            try:
                url = base_url.rstrip('/') + endpoint
                response = requests.head(url, timeout=5, allow_redirects=False, verify=False)
                if response.status_code in [200, 301, 302, 403]:
                    discovered.append(endpoint)
                    self.logger.debug(f"Found endpoint: {endpoint} (Status: {response.status_code})")
            except:
                pass
        
        return discovered
