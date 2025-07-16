"""
SecurityWatch Pro - Event Data Models
"""

from datetime import datetime
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class SecurityEvent:
    """Individual security event data structure"""
    timestamp: datetime
    event_type: str  # failed_login, brute_force, suspicious_ip, etc.
    source_ip: str
    username: str
    hostname: str
    details: str
    severity: str  # low, medium, high, critical
    log_source: str


@dataclass
class ThreatPattern:
    """Threat pattern configuration"""
    name: str
    description: str
    regex_pattern: str
    severity: str
    enabled: bool = True
    threshold_count: int = 5
    time_window: int = 300  # seconds


@dataclass
class AlertConfig:
    """Alert configuration settings"""
    email_enabled: bool = True
    console_enabled: bool = True
    log_enabled: bool = True
    report_enabled: bool = True
    alert_frequency: int = 15  # Minutes between alerts
    severity_threshold: str = "medium"  # minimum severity to alert


@dataclass
class EmailConfig:
    """Email configuration with encryption"""
    smtp_server: str = ""
    smtp_port: int = 587
    username: str = ""
    password: str = ""  # Will be encrypted
    from_email: str = ""
    to_emails: List[str] = None
    use_tls: bool = True
    enabled: bool = False

    def __post_init__(self):
        if self.to_emails is None:
            self.to_emails = []


@dataclass
class MonitoringConfig:
    """System monitoring configuration"""
    log_paths: List[str] = None
    check_interval: int = 60  # seconds
    max_events_memory: int = 10000
    database_retention_days: int = 30
    auto_detect_logs: bool = True
    monitor_system_events: bool = True

    def __post_init__(self):
        if self.log_paths is None:
            self.log_paths = []
