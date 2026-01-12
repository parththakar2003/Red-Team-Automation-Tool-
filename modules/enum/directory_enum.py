"""
Directory Enumeration Module
Discovers directories and endpoints on web applications
"""
import requests
from typing import List
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.logger import Logger
from core.config import get_config


class DirectoryEnumerator:
    """Directory and endpoint discovery"""
    
    # Common directories and files to check
    COMMON_PATHS = [
        # Admin panels
        'admin', 'administrator', 'wp-admin', 'cpanel', 'control-panel',
        'admin.php', 'admin/', 'login', 'login.php', 'signin',
        
        # Configuration files
        'config', 'config.php', 'configuration.php', 'settings.php',
        'web.config', 'database.yml', '.env', 'config.json',
        
        # Backup files
        'backup', 'backups', 'backup.zip', 'backup.sql', 'backup.tar.gz',
        'old', 'old/', 'backup.old', 'site.zip',
        
        # Documentation
        'docs', 'documentation', 'doc', 'readme.txt', 'README.md',
        
        # Development
        'dev', 'development', 'test', 'testing', 'staging',
        'debug', 'temp', 'tmp',
        
        # APIs
        'api', 'api/', 'api/v1', 'api/v2', 'rest', 'graphql',
        
        # Common files
        'robots.txt', 'sitemap.xml', 'crossdomain.xml',
        '.htaccess', '.git', '.svn', '.env',
        
        # Uploads
        'uploads', 'upload', 'files', 'media', 'images', 'img',
        
        # Sensitive
        'phpinfo.php', 'info.php', 'test.php', 'shell.php',
        '.git/config', '.git/HEAD', '.DS_Store',
    ]
    
    def __init__(self):
        """Initialize directory enumerator"""
        self.logger = Logger.get(__name__)
        self.config = get_config()
        self.timeout = self.config.get('scan.connection_timeout', 10)
        self.max_threads = self.config.get('scan.max_threads', 10)
        self.user_agent = self.config.get('scan.user_agent',
                                         'Mozilla/5.0 Red Team Assessment Tool')
    
    def enumerate(self, base_url: str, wordlist: List[str] = None) -> List[str]:
        """
        Enumerate directories and files
        
        Args:
            base_url: Base URL to enumerate
            wordlist: Custom wordlist (uses default if None)
            
        Returns:
            List of discovered paths
        """
        self.logger.info(f"Starting directory enumeration on {base_url}")
        
        if wordlist is None:
            wordlist = self._get_wordlist()
        
        discovered = []
        base_url = base_url.rstrip('/')
        
        # Use thread pool for concurrent requests
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self._check_path, base_url, path): path
                for path in wordlist
            }
            
            for future in as_completed(futures):
                path = futures[future]
                try:
                    result = future.result()
                    if result:
                        discovered.append(result)
                        self.logger.info(f"Found: {result['path']} (Status: {result['status']})")
                except Exception as e:
                    self.logger.debug(f"Error checking {path}: {e}")
        
        self.logger.info(f"Directory enumeration complete - {len(discovered)} paths discovered")
        
        return [d['path'] for d in discovered]
    
    def _get_wordlist(self) -> List[str]:
        """Get wordlist based on configuration"""
        wordlist_size = self.config.get('enumeration.directory_wordlist_size', 'medium')
        
        if wordlist_size == 'small':
            return self.COMMON_PATHS[:20]
        elif wordlist_size == 'large':
            return self.COMMON_PATHS + self._generate_extensions()
        else:  # medium
            return self.COMMON_PATHS[:50]
    
    def _generate_extensions(self) -> List[str]:
        """Generate additional paths with extensions"""
        extensions = ['.php', '.asp', '.aspx', '.jsp', '.html', '.txt', '.bak', '.old']
        base_names = ['index', 'admin', 'login', 'config', 'backup', 'test']
        
        paths = []
        for name in base_names:
            for ext in extensions:
                paths.append(f"{name}{ext}")
        
        return paths
    
    def _check_path(self, base_url: str, path: str) -> dict:
        """
        Check if path exists
        
        Args:
            base_url: Base URL
            path: Path to check
            
        Returns:
            Dict with path info if exists, None otherwise
        """
        path = path.lstrip('/')
        url = f"{base_url}/{path}"
        
        try:
            headers = {'User-Agent': self.user_agent}
            response = requests.get(url, headers=headers, timeout=self.timeout,
                                   allow_redirects=False, verify=False)
            
            # Consider successful if status is 200, 301, 302, 401, or 403
            # 401/403 means path exists but requires auth or is forbidden
            if response.status_code in [200, 301, 302, 401, 403]:
                return {
                    'path': f"/{path}",
                    'status': response.status_code,
                    'size': len(response.content),
                    'url': url
                }
        except requests.Timeout:
            self.logger.debug(f"Timeout checking {path}")
        except requests.RequestException as e:
            self.logger.debug(f"Request failed for {path}: {e}")
        except Exception as e:
            self.logger.debug(f"Error checking {path}: {e}")
        
        return None
    
    def smart_enumerate(self, base_url: str) -> dict:
        """
        Perform smart enumeration with analysis
        
        Args:
            base_url: Base URL
            
        Returns:
            Dict with categorized findings
        """
        self.logger.info("Performing smart directory enumeration")
        
        discovered = self.enumerate(base_url)
        
        # Categorize findings
        categorized = {
            'admin_panels': [],
            'config_files': [],
            'backups': [],
            'sensitive': [],
            'development': [],
            'other': []
        }
        
        for path in discovered:
            path_lower = path.lower()
            
            if any(x in path_lower for x in ['admin', 'control', 'cpanel', 'login']):
                categorized['admin_panels'].append(path)
            elif any(x in path_lower for x in ['config', '.env', 'settings', 'database']):
                categorized['config_files'].append(path)
            elif any(x in path_lower for x in ['backup', '.bak', '.old', '.sql']):
                categorized['backups'].append(path)
            elif any(x in path_lower for x in ['.git', '.svn', 'phpinfo', 'shell']):
                categorized['sensitive'].append(path)
            elif any(x in path_lower for x in ['dev', 'test', 'staging', 'debug']):
                categorized['development'].append(path)
            else:
                categorized['other'].append(path)
        
        return categorized
