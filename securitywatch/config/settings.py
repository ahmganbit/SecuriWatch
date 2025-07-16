"""
SecurityWatch Pro - Configuration Management
"""

import os
import json
import base64
import hashlib
import platform
from pathlib import Path
from dataclasses import asdict
from cryptography.fernet import Fernet
from typing import List

from ..models.events import EmailConfig, AlertConfig, MonitoringConfig


class SecurityWatchConfig:
    """Configuration management for SecurityWatch Pro"""
    
    def __init__(self, config_file: str = "securitywatch_config.json"):
        self.config_file = Path(config_file)
        self.encryption_key = None
        self._load_or_create_config()
    
    def _generate_key(self) -> bytes:
        """Generate encryption key from system info"""
        try:
            username = os.getlogin()
        except OSError:
            username = os.environ.get('USER', os.environ.get('USERNAME', 'default'))
        
        system_info = f"{username}{platform.node()}SecurityWatchPro"
        return base64.urlsafe_b64encode(hashlib.sha256(system_info.encode()).digest())
    
    def _encrypt_password(self, password: str) -> str:
        """Encrypt password for secure storage"""
        if not password:
            return ""
        
        if not self.encryption_key:
            self.encryption_key = self._generate_key()
        
        fernet = Fernet(self.encryption_key)
        return fernet.encrypt(password.encode()).decode()
    
    def _decrypt_password(self, encrypted_password: str) -> str:
        """Decrypt password for use"""
        if not encrypted_password:
            return ""
        
        if not self.encryption_key:
            self.encryption_key = self._generate_key()
        
        try:
            fernet = Fernet(self.encryption_key)
            return fernet.decrypt(encrypted_password.encode()).decode()
        except Exception:
            return ""
    
    def _load_or_create_config(self):
        """Load existing config or create default"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    config_data = json.load(f)
                    self._parse_config(config_data)
            except Exception as e:
                print(f"Error loading config: {e}")
                self._create_default_config()
        else:
            self._create_default_config()
    
    def _create_default_config(self):
        """Create default configuration"""
        self.email = EmailConfig(to_emails=[])
        self.alerts = AlertConfig()
        self.monitoring = MonitoringConfig()
        
        # Auto-detect log paths based on OS
        self.monitoring.log_paths = self._detect_log_paths()
        
        self.save_config()
    
    def _detect_log_paths(self) -> List[str]:
        """Auto-detect system log paths"""
        system = platform.system().lower()
        log_paths = []
        
        if system == "linux":
            potential_paths = [
                "/var/log/auth.log",      # Ubuntu/Debian
                "/var/log/secure",        # CentOS/RHEL
                "/var/log/messages",      # General system logs
                "/var/log/syslog",        # Ubuntu/Debian syslog
                "/var/log/httpd/access_log",  # Apache
                "/var/log/apache2/access.log", # Apache Ubuntu
                "/var/log/nginx/access.log",   # Nginx
                "/var/log/fail2ban.log",       # Fail2ban
                "/var/log/kern.log"            # Kernel logs
            ]
        elif system == "darwin":  # macOS
            potential_paths = [
                "/var/log/system.log",
                "/var/log/auth.log",
                "/private/var/log/secure.log",
                "/var/log/wifi.log"
            ]
        elif system == "windows":
            potential_paths = [
                "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
                "C:\\Windows\\System32\\winevt\\Logs\\System.evtx",
                "C:\\Windows\\System32\\winevt\\Logs\\Application.evtx"
            ]
        
        # Check which paths exist and are readable
        for path in potential_paths:
            path_obj = Path(path)
            if path_obj.exists():
                try:
                    # Test if we can read the file
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        f.read(1)
                    log_paths.append(path)
                except (PermissionError, UnicodeDecodeError):
                    # Skip files we can't read
                    continue
        
        return log_paths
    
    def _parse_config(self, config_data: dict):
        """Parse configuration from JSON"""
        # Parse email config
        email_data = config_data.get('email', {})
        if 'password' in email_data and email_data['password']:
            email_data['password'] = self._decrypt_password(email_data['password'])
        self.email = EmailConfig(**email_data)
        
        # Parse other configs
        self.alerts = AlertConfig(**config_data.get('alerts', {}))
        
        monitoring_data = config_data.get('monitoring', {})
        if 'log_paths' not in monitoring_data or not monitoring_data['log_paths']:
            monitoring_data['log_paths'] = self._detect_log_paths()
        self.monitoring = MonitoringConfig(**monitoring_data)
    
    def save_config(self):
        """Save configuration to file"""
        config_data = {
            'email': asdict(self.email),
            'alerts': asdict(self.alerts),
            'monitoring': asdict(self.monitoring),
            'version': '1.0.0'
        }
        
        # Encrypt password before saving
        if config_data['email']['password']:
            config_data['email']['password'] = self._encrypt_password(config_data['email']['password'])
        
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config_data, f, indent=2, default=str)
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def update_email_config(self, smtp_server: str, smtp_port: int, username: str, 
                           password: str, from_email: str, to_emails: List[str]):
        """Update email configuration"""
        self.email.smtp_server = smtp_server
        self.email.smtp_port = smtp_port
        self.email.username = username
        self.email.password = password
        self.email.from_email = from_email
        self.email.to_emails = to_emails
        self.email.enabled = bool(smtp_server and username and password)
        self.save_config()
    
    def add_log_path(self, log_path: str):
        """Add a log path to monitoring"""
        if log_path not in self.monitoring.log_paths:
            self.monitoring.log_paths.append(log_path)
            self.save_config()
    
    def remove_log_path(self, log_path: str):
        """Remove a log path from monitoring"""
        if log_path in self.monitoring.log_paths:
            self.monitoring.log_paths.remove(log_path)
            self.save_config()
    
    def get_config_summary(self) -> dict:
        """Get configuration summary for display"""
        return {
            'email_configured': self.email.enabled,
            'log_paths_count': len(self.monitoring.log_paths),
            'check_interval': self.monitoring.check_interval,
            'alert_frequency': self.alerts.alert_frequency,
            'severity_threshold': self.alerts.severity_threshold,
            'database_retention_days': self.monitoring.database_retention_days
        }
