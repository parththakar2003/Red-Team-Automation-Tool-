"""
Configuration Manager for Red Team Framework
Handles loading and accessing configuration settings
"""
import os
import yaml
from pathlib import Path
from typing import Any, Dict


class ConfigManager:
    """Manages application configuration"""
    
    def __init__(self, config_path: str = None):
        """
        Initialize configuration manager
        
        Args:
            config_path: Path to config.yaml file
        """
        if config_path is None:
            # Default to config.yaml in project root
            project_root = Path(__file__).parent.parent
            config_path = os.path.join(project_root, "config.yaml")
        
        self.config_path = config_path
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")
        except yaml.YAMLError as e:
            raise ValueError(f"Error parsing configuration file: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value by key (supports dot notation)
        
        Args:
            key: Configuration key (e.g., 'scan.timeout')
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """
        Get entire configuration section
        
        Args:
            section: Section name (e.g., 'scan', 'recon')
            
        Returns:
            Configuration section dictionary
        """
        return self.config.get(section, {})
    
    def reload(self):
        """Reload configuration from file"""
        self.config = self._load_config()


# Global configuration instance
_config_instance = None


def get_config(config_path: str = None) -> ConfigManager:
    """
    Get global configuration instance
    
    Args:
        config_path: Path to config file (only used on first call)
        
    Returns:
        ConfigManager instance
    """
    global _config_instance
    if _config_instance is None:
        _config_instance = ConfigManager(config_path)
    return _config_instance
