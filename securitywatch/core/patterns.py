"""
SecurityWatch Pro - Log Pattern Matching
"""

import re
import socket
from datetime import datetime
from typing import List

from ..models.events import SecurityEvent, ThreatPattern


class LogPatternMatcher:
    """Advanced pattern matching for security events"""
    
    def __init__(self):
        self.patterns = self._initialize_patterns()
    
    def _initialize_patterns(self) -> List[ThreatPattern]:
        """Initialize default threat patterns"""
        return [
            # SSH Failed Login Patterns
            ThreatPattern(
                name="SSH Failed Login",
                description="Failed SSH authentication attempts",
                regex_pattern=r"Failed password for (?P<username>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)",
                severity="medium"
            ),
            ThreatPattern(
                name="SSH Invalid User",
                description="SSH login attempts with invalid usernames",
                regex_pattern=r"Invalid user (?P<username>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)",
                severity="high"
            ),
            
            # Windows Failed Login Patterns
            ThreatPattern(
                name="Windows Failed Login",
                description="Windows logon failures",
                regex_pattern=r"Logon Type:\s+(?P<logon_type>\d+).*Source Network Address:\s+(?P<ip>\d+\.\d+\.\d+\.\d+).*Account Name:\s+(?P<username>\S+)",
                severity="medium"
            ),
            
            # Brute Force Patterns
            ThreatPattern(
                name="Rapid Failed Logins",
                description="Multiple failed login attempts in short time",
                regex_pattern=r"authentication failure.*user=(?P<username>\S+)",
                severity="high",
                threshold_count=10,
                time_window=300
            ),
            
            # Web Application Attacks
            ThreatPattern(
                name="SQL Injection Attempt",
                description="Potential SQL injection in web logs",
                regex_pattern=r"(?P<ip>\d+\.\d+\.\d+\.\d+).*(?:union|select|insert|delete|drop|exec).*(?:'|--|;)",
                severity="critical"
            ),
            
            # System Intrusion
            ThreatPattern(
                name="Privilege Escalation",
                description="Potential privilege escalation attempts",
                regex_pattern=r"(?P<username>\S+).*(?:sudo|su|admin|root).*(?:FAILED|denied)",
                severity="high"
            ),
            
            # Network Scanning
            ThreatPattern(
                name="Port Scanning",
                description="Potential port scanning activity",
                regex_pattern=r"(?P<ip>\d+\.\d+\.\d+\.\d+).*(?:connection refused|timeout|unreachable)",
                severity="medium",
                threshold_count=20
            ),
            
            # Additional Security Patterns
            ThreatPattern(
                name="Suspicious File Access",
                description="Access to sensitive system files",
                regex_pattern=r"(?P<username>\S+).*(?:/etc/passwd|/etc/shadow|/etc/hosts|\.ssh/)",
                severity="high"
            ),
            
            ThreatPattern(
                name="Command Injection",
                description="Potential command injection attempts",
                regex_pattern=r"(?P<ip>\d+\.\d+\.\d+\.\d+).*(?:\||;|`|\$\(|&&)",
                severity="critical"
            ),
            
            ThreatPattern(
                name="Directory Traversal",
                description="Directory traversal attack attempts",
                regex_pattern=r"(?P<ip>\d+\.\d+\.\d+\.\d+).*(?:\.\./|\.\.\\\|%2e%2e)",
                severity="high"
            ),

            ThreatPattern(
                name="Failed Root Login",
                description="Failed root login attempts",
                regex_pattern=r"Failed password for root from (?P<ip>\d+\.\d+\.\d+\.\d+)",
                severity="critical"
            ),

            ThreatPattern(
                name="Multiple Authentication Failures",
                description="Multiple authentication failures from same IP",
                regex_pattern=r"authentication failure.*rhost=(?P<ip>\d+\.\d+\.\d+\.\d+)",
                severity="high",
                threshold_count=5
            )
        ]
    
    def match_patterns(self, log_line: str, log_source: str) -> List[SecurityEvent]:
        """Match log line against all threat patterns"""
        events = []
        
        for pattern in self.patterns:
            if not pattern.enabled:
                continue
            
            match = re.search(pattern.regex_pattern, log_line, re.IGNORECASE)
            if match:
                event = SecurityEvent(
                    timestamp=datetime.now(),
                    event_type=pattern.name.lower().replace(' ', '_'),
                    source_ip=match.groupdict().get('ip', ''),
                    username=match.groupdict().get('username', ''),
                    hostname=socket.gethostname(),
                    details=log_line.strip(),
                    severity=pattern.severity,
                    log_source=log_source
                )
                events.append(event)
        
        return events
    
    def add_custom_pattern(self, pattern: ThreatPattern):
        """Add a custom threat pattern"""
        self.patterns.append(pattern)
    
    def remove_pattern(self, pattern_name: str):
        """Remove a threat pattern by name"""
        self.patterns = [p for p in self.patterns if p.name != pattern_name]
    
    def get_patterns(self) -> List[ThreatPattern]:
        """Get all current patterns"""
        return self.patterns.copy()
    
    def enable_pattern(self, pattern_name: str):
        """Enable a specific pattern"""
        for pattern in self.patterns:
            if pattern.name == pattern_name:
                pattern.enabled = True
                break
    
    def disable_pattern(self, pattern_name: str):
        """Disable a specific pattern"""
        for pattern in self.patterns:
            if pattern.name == pattern_name:
                pattern.enabled = False
                break
