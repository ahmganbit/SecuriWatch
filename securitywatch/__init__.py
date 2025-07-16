"""
SecurityWatch Pro - Advanced Security Monitoring System
Copyright (c) 2025 SysAdmin Tools Pro
Version: 1.0.0

Professional security monitoring with intelligent pattern recognition, automated threat detection,
and comprehensive reporting for Windows, Linux, and macOS systems.
"""

__version__ = "1.0.0"
__author__ = "SysAdmin Tools Pro"
__email__ = "support@sysadmintoolspro.com"

from .core.monitor import SecurityWatchMonitor
from .core.database import SecurityDatabase
from .core.analyzer import ThreatAnalyzer
from .core.patterns import LogPatternMatcher
from .config.settings import SecurityWatchConfig
from .models.events import SecurityEvent, ThreatPattern, AlertConfig, EmailConfig, MonitoringConfig

__all__ = [
    'SecurityWatchMonitor',
    'SecurityDatabase', 
    'ThreatAnalyzer',
    'LogPatternMatcher',
    'SecurityWatchConfig',
    'SecurityEvent',
    'ThreatPattern',
    'AlertConfig',
    'EmailConfig',
    'MonitoringConfig'
]
