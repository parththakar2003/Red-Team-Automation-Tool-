"""
Port Scanner Module
Performs TCP/UDP port scanning and service detection
"""
import nmap
import socket
from typing import List
from core.logger import Logger
from core.config import get_config
from core.models import ScanResult, Port


class PortScanner:
    """Network port scanner with service detection"""
    
    def __init__(self):
        """Initialize port scanner"""
        self.logger = Logger.get(__name__)
        self.config = get_config()
        self.nm = nmap.PortScanner()
    
    def scan(self, target: str) -> ScanResult:
        """
        Perform port scan on target
        
        Args:
            target: IP address or hostname to scan
            
        Returns:
            ScanResult with discovered ports and services
        """
        self.logger.info(f"Starting port scan on {target}")
        
        result = ScanResult(target=target)
        
        # Determine ports to scan
        if self.config.get('scanning.full_scan', False):
            port_range = '1-65535'
            self.logger.info("Performing full port scan (1-65535)")
        else:
            common_ports = self.config.get('scanning.common_ports', [])
            if common_ports:
                port_range = ','.join(map(str, common_ports))
                self.logger.info(f"Scanning {len(common_ports)} common ports")
            else:
                port_range = '1-1000'
                self.logger.info("Scanning ports 1-1000")
        
        # Build nmap arguments
        scan_args = '-sV'  # Service version detection
        
        if self.config.get('scanning.service_detection', True):
            scan_args += ' --version-intensity 5'
        
        if self.config.get('scanning.os_detection', False):
            scan_args += ' -O'
        
        # Add timing template for speed/stealth balance
        scan_args += ' -T4'
        
        try:
            self.logger.debug(f"Running nmap: {scan_args} -p {port_range}")
            self.nm.scan(target, port_range, arguments=scan_args)
            
            # Parse results
            if target in self.nm.all_hosts():
                host = self.nm[target]
                
                # Extract OS information if available
                if 'osmatch' in host and host['osmatch']:
                    result.os_detection = {
                        'name': host['osmatch'][0].get('name', 'Unknown'),
                        'accuracy': host['osmatch'][0].get('accuracy', '0'),
                        'os_class': host['osmatch'][0].get('osclass', [])
                    }
                    self.logger.info(f"OS Detection: {result.os_detection['name']} "
                                   f"(Accuracy: {result.os_detection['accuracy']}%)")
                
                # Extract port information
                for proto in ['tcp', 'udp']:
                    if proto in host:
                        for port_num, port_data in host[proto].items():
                            port = Port(
                                number=port_num,
                                protocol=proto,
                                state=port_data.get('state', 'unknown'),
                                service=port_data.get('name', ''),
                                version=self._format_version(port_data),
                                banner=port_data.get('product', '')
                            )
                            result.ports.append(port)
                            
                            if port.state == 'open':
                                self.logger.info(f"Open port: {port.number}/{proto} - "
                                               f"{port.service} {port.version or ''}")
            
            else:
                self.logger.warning(f"Host {target} appears down or unreachable")
                # Try basic connectivity check
                if self._check_host_up(target):
                    self.logger.info("Host is up but ports may be filtered")
        
        except nmap.PortScannerError as e:
            self.logger.error(f"Nmap scan error: {e}")
            # Fallback to basic socket scanning
            self.logger.info("Falling back to basic socket scan")
            result = self._basic_socket_scan(target)
        except Exception as e:
            self.logger.error(f"Port scan failed: {e}")
        
        open_count = len([p for p in result.ports if p.state == 'open'])
        self.logger.info(f"Scan complete - {open_count} open ports found")
        
        return result
    
    def _format_version(self, port_data: dict) -> str:
        """Format version string from port data"""
        parts = []
        
        if 'product' in port_data and port_data['product']:
            parts.append(port_data['product'])
        
        if 'version' in port_data and port_data['version']:
            parts.append(port_data['version'])
        
        if 'extrainfo' in port_data and port_data['extrainfo']:
            parts.append(f"({port_data['extrainfo']})")
        
        return ' '.join(parts) if parts else None
    
    def _check_host_up(self, target: str) -> bool:
        """
        Check if host is reachable
        
        Args:
            target: Target IP or hostname
            
        Returns:
            True if host is up
        """
        try:
            # Try ping-like check on port 80
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((target, 80))
            sock.close()
            return result == 0 or result == 111  # Connected or connection refused (but host up)
        except:
            return False
    
    def _basic_socket_scan(self, target: str) -> ScanResult:
        """
        Fallback basic socket-based port scan
        
        Args:
            target: Target to scan
            
        Returns:
            ScanResult
        """
        result = ScanResult(target=target)
        common_ports = self.config.get('scanning.common_ports', [80, 443, 22, 21, 25])
        
        self.logger.info(f"Performing basic socket scan on {len(common_ports)} ports")
        
        for port_num in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result_code = sock.connect_ex((target, port_num))
                
                if result_code == 0:
                    # Try to grab banner
                    banner = self._grab_banner(sock)
                    
                    port = Port(
                        number=port_num,
                        protocol='tcp',
                        state='open',
                        service=self._guess_service(port_num),
                        banner=banner
                    )
                    result.ports.append(port)
                    self.logger.info(f"Open port: {port_num}/tcp")
                
                sock.close()
            except Exception as e:
                self.logger.debug(f"Error scanning port {port_num}: {e}")
        
        return result
    
    def _grab_banner(self, sock: socket.socket) -> str:
        """
        Attempt to grab service banner
        
        Args:
            sock: Connected socket
            
        Returns:
            Banner string or empty
        """
        try:
            sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:200]  # Limit banner length
        except:
            return ""
    
    def _guess_service(self, port: int) -> str:
        """
        Guess service based on common port numbers
        
        Args:
            port: Port number
            
        Returns:
            Service name
        """
        common_services = {
            20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet',
            25: 'smtp', 53: 'dns', 80: 'http', 110: 'pop3',
            143: 'imap', 443: 'https', 445: 'smb', 3306: 'mysql',
            3389: 'rdp', 5432: 'postgresql', 5900: 'vnc',
            8080: 'http-proxy', 8443: 'https-alt'
        }
        return common_services.get(port, 'unknown')
