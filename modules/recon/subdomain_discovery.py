"""
Subdomain Discovery Module
Discovers subdomains through various techniques
"""
import requests
from typing import List, Set
from core.logger import Logger
from core.config import get_config


class SubdomainDiscovery:
    """Subdomain discovery through passive and active techniques"""
    
    # Common subdomain prefixes for active brute force
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
        'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
        'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3',
        'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static',
        'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki',
        'web', 'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal', 'video',
        'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4', 'www3', 'dns', 'search',
        'staging', 'server', 'mx1', 'chat', 'wap', 'my', 'svn', 'mail1', 'sites',
        'proxy', 'ads', 'host', 'crm', 'cms', 'backup', 'mx2', 'lyncdiscover', 'info',
        'apps', 'download', 'remote', 'db', 'forums', 'store', 'relay', 'files',
        'newsletter', 'app', 'live', 'owa', 'en', 'start', 'sms', 'office', 'exchange',
        'ipv4', 'help', 'home', 'library', 'ftp2', 'ntp', 'monitor', 'login', 'service',
        'correo', 'www4', 'moodle', 'it', 'gateway', 'gw', 'i', 'stat', 'stage',
        'ldap', 'tv', 'ssl', 'web1', 'telnet', 'radius', 'vpn2', 'dns3', 'erp', 'ci'
    ]
    
    def __init__(self):
        """Initialize subdomain discovery"""
        self.logger = Logger.get(__name__)
        self.config = get_config()
        self.timeout = self.config.get('scan.connection_timeout', 10)
    
    def discover(self, domain: str) -> List[str]:
        """
        Discover subdomains for target domain
        
        Args:
            domain: Target domain
            
        Returns:
            List of discovered subdomains
        """
        self.logger.info(f"Starting subdomain discovery for {domain}")
        
        subdomains: Set[str] = set()
        
        # Passive discovery
        if self.config.get('recon.enable_passive_recon', True):
            passive_subs = self._passive_discovery(domain)
            subdomains.update(passive_subs)
            self.logger.debug(f"Passive discovery found {len(passive_subs)} subdomains")
        
        # Active brute force with common names
        wordlist_size = self.config.get('recon.subdomain_wordlist_size', 'medium')
        active_subs = self._active_bruteforce(domain, wordlist_size)
        subdomains.update(active_subs)
        self.logger.debug(f"Active discovery found {len(active_subs)} subdomains")
        
        result = sorted(list(subdomains))
        self.logger.info(f"Total subdomains discovered: {len(result)}")
        
        return result
    
    def _passive_discovery(self, domain: str) -> Set[str]:
        """
        Passive subdomain discovery using public sources
        
        Args:
            domain: Target domain
            
        Returns:
            Set of subdomains
        """
        subdomains: Set[str] = set()
        
        # Use crt.sh certificate transparency logs
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    if name:
                        # Handle wildcard and multiple names
                        for sub in name.split('\n'):
                            sub = sub.strip().replace('*.', '')
                            if sub.endswith(domain) and sub != domain:
                                subdomains.add(sub)
        except Exception as e:
            self.logger.debug(f"crt.sh query failed: {e}")
        
        return subdomains
    
    def _active_bruteforce(self, domain: str, wordlist_size: str = 'medium') -> Set[str]:
        """
        Active subdomain bruteforce using DNS resolution
        
        Args:
            domain: Target domain
            wordlist_size: Size of wordlist (small, medium, large)
            
        Returns:
            Set of valid subdomains
        """
        import dns.resolver
        
        subdomains: Set[str] = set()
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        
        # Determine wordlist based on size
        if wordlist_size == 'small':
            wordlist = self.COMMON_SUBDOMAINS[:25]
        elif wordlist_size == 'large':
            wordlist = self.COMMON_SUBDOMAINS
        else:  # medium
            wordlist = self.COMMON_SUBDOMAINS[:50]
        
        self.logger.debug(f"Testing {len(wordlist)} common subdomains")
        
        for prefix in wordlist:
            subdomain = f"{prefix}.{domain}"
            try:
                # Try to resolve the subdomain
                answers = resolver.resolve(subdomain, 'A')
                if answers:
                    subdomains.add(subdomain)
                    self.logger.debug(f"Found: {subdomain}")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                pass
            except Exception as e:
                self.logger.debug(f"Error resolving {subdomain}: {e}")
        
        return subdomains
    
    def check_subdomain_takeover(self, subdomain: str) -> bool:
        """
        Check if subdomain is vulnerable to takeover
        
        Args:
            subdomain: Subdomain to check
            
        Returns:
            True if potentially vulnerable
        """
        # Signatures of services vulnerable to subdomain takeover
        vulnerable_signatures = [
            'There is no app configured at that hostname',
            'NoSuchBucket',
            'No Such Account',
            'You're Almost Done',
            'Trying to access your account?',
            'Project doesnt exist',
        ]
        
        try:
            response = requests.get(f"http://{subdomain}", timeout=self.timeout, 
                                   allow_redirects=True)
            content = response.text
            
            for signature in vulnerable_signatures:
                if signature in content:
                    self.logger.warning(f"Potential subdomain takeover: {subdomain}")
                    return True
        except Exception as e:
            self.logger.debug(f"Subdomain takeover check failed for {subdomain}: {e}")
        
        return False
