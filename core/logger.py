"""
Logging utilities for Red Team Framework
"""
import logging
import os
from pathlib import Path
from datetime import datetime
from core.config import get_config


class Logger:
    """Custom logger for the framework"""
    
    _loggers = {}
    
    @staticmethod
    def setup(name: str = "redteam") -> logging.Logger:
        """
        Setup and return a logger instance
        
        Args:
            name: Logger name
            
        Returns:
            Configured logger instance
        """
        if name in Logger._loggers:
            return Logger._loggers[name]
        
        config = get_config()
        
        # Create logger
        logger = logging.getLogger(name)
        logger.setLevel(getattr(logging, config.get('logging.level', 'INFO')))
        
        # Remove existing handlers
        logger.handlers = []
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_format = logging.Formatter(
            '%(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_format)
        logger.addHandler(console_handler)
        
        # File handler
        if config.get('logging.log_to_file', True):
            log_file = config.get('logging.log_file', 'logs/redteam.log')
            log_dir = os.path.dirname(log_file)
            
            # Create log directory
            if log_dir:
                Path(log_dir).mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            file_format = logging.Formatter(
                config.get('logging.log_format', 
                          '[%(asctime)s] %(levelname)s - %(name)s - %(message)s')
            )
            file_handler.setFormatter(file_format)
            logger.addHandler(file_handler)
        
        Logger._loggers[name] = logger
        return logger
    
    @staticmethod
    def get(name: str = "redteam") -> logging.Logger:
        """Get or create logger"""
        if name not in Logger._loggers:
            return Logger.setup(name)
        return Logger._loggers[name]
