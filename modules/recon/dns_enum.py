"""
DNS Enumeration Module
Performs comprehensive DNS reconnaissance
"""
import dns.resolver
import dns.reversename
from typing import Dict, List
from core.logger import Logger
from core.config import get_config
from core.models import ReconResult


class DNSEnumerator:
    """DNS enumeration and reconnaissance"""
    
    # Common DNS record types to query
    RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
    
    def __init__(self):
        """Initialize DNS enumerator"""
        self.logger = Logger.get(__name__)
        self.config = get_config()
        
        # Configure DNS resolver
        self.resolver = dns.resolver.Resolver()
        dns_servers = self.config.get('recon.dns_servers', ['8.8.8.8', '8.8.4.4'])
        self.resolver.nameservers = dns_servers
        self.resolver.timeout = self.config.get('scan.timeout', 30)
        self.resolver.lifetime = self.config.get('scan.timeout', 30)
    
    def enumerate(self, target: str) -> ReconResult:
        """
        Perform DNS enumeration on target
        
        Args:
            target: Domain name to enumerate
            
        Returns:
            ReconResult with DNS information
        """
        self.logger.info(f"Starting DNS enumeration for {target}")
        
        result = ReconResult(target=target)
        
        # Query all record types
        for record_type in self.RECORD_TYPES:
            records = self._query_record(target, record_type)
            if records:
                result.dns_records[record_type] = records
                self.logger.debug(f"Found {len(records)} {record_type} records")
        
        # Extract IP addresses from A and AAAA records
        if 'A' in result.dns_records:
            result.ip_addresses.extend(result.dns_records['A'])
        if 'AAAA' in result.dns_records:
            result.ip_addresses.extend(result.dns_records['AAAA'])
        
        # Perform reverse DNS on IPs
        for ip in result.ip_addresses[:5]:  # Limit to first 5 IPs
            reverse = self._reverse_dns(ip)
            if reverse:
                result.metadata[f'reverse_{ip}'] = reverse
        
        # Attempt subdomain discovery
        if self.config.get('recon.enable_passive_recon', True):
            from modules.recon.subdomain_discovery import SubdomainDiscovery
            subdomain_enum = SubdomainDiscovery()
            result.subdomains = subdomain_enum.discover(target)
        
        self.logger.info(f"DNS enumeration complete - Found {len(result.dns_records)} record types")
        
        return result
    
    def _query_record(self, target: str, record_type: str) -> List[str]:
        """
        Query specific DNS record type
        
        Args:
            target: Domain name
            record_type: DNS record type (A, MX, TXT, etc.)
            
        Returns:
            List of record values
        """
        records = []
        try:
            answers = self.resolver.resolve(target, record_type)
            for rdata in answers:
                records.append(str(rdata))
        except dns.resolver.NXDOMAIN:
            self.logger.debug(f"Domain {target} does not exist")
        except dns.resolver.NoAnswer:
            self.logger.debug(f"No {record_type} records for {target}")
        except dns.resolver.Timeout:
            self.logger.warning(f"DNS query timeout for {target} {record_type}")
        except Exception as e:
            self.logger.debug(f"DNS query failed for {target} {record_type}: {e}")
        
        return records
    
    def _reverse_dns(self, ip: str) -> str:
        """
        Perform reverse DNS lookup
        
        Args:
            ip: IP address
            
        Returns:
            Hostname or empty string
        """
        try:
            rev_name = dns.reversename.from_address(ip)
            answers = self.resolver.resolve(rev_name, 'PTR')
            return str(answers[0]) if answers else ""
        except Exception as e:
            self.logger.debug(f"Reverse DNS failed for {ip}: {e}")
            return ""
    
    def enumerate_zone_transfer(self, target: str) -> List[str]:
        """
        Attempt DNS zone transfer (educational purpose only)
        
        Args:
            target: Domain name
            
        Returns:
            List of records from zone transfer
        """
        self.logger.info(f"Checking for zone transfer misconfiguration on {target}")
        
        records = []
        try:
            # Get nameservers
            ns_records = self._query_record(target, 'NS')
            
            for ns in ns_records:
                ns = ns.rstrip('.')
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, target, timeout=10))
                    for name, node in zone.nodes.items():
                        records.append(f"{name}.{target}")
                    self.logger.warning(f"Zone transfer successful on {ns} - SECURITY ISSUE!")
                except Exception as e:
                    self.logger.debug(f"Zone transfer failed on {ns}: {e}")
        except Exception as e:
            self.logger.debug(f"Zone transfer enumeration error: {e}")
        
        return records
