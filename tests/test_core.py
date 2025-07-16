"""
SecurityWatch Pro - Core Component Tests
"""

import pytest
import tempfile
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

from securitywatch.core.database import SecurityDatabase
from securitywatch.core.patterns import LogPatternMatcher
from securitywatch.core.analyzer import ThreatAnalyzer
from securitywatch.models.events import SecurityEvent, ThreatPattern


class TestSecurityDatabase:
    """Test SecurityDatabase functionality"""
    
    def setup_method(self):
        """Setup test database"""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.temp_db.close()
        self.db = SecurityDatabase(self.temp_db.name)
    
    def teardown_method(self):
        """Cleanup test database"""
        Path(self.temp_db.name).unlink(missing_ok=True)
    
    def test_database_initialization(self):
        """Test database tables are created"""
        conn = sqlite3.connect(self.temp_db.name)
        cursor = conn.cursor()
        
        # Check if tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        assert 'security_events' in tables
        assert 'threat_patterns' in tables
        assert 'ip_reputation' in tables
        
        conn.close()
    
    def test_add_event(self):
        """Test adding security events"""
        event = SecurityEvent(
            timestamp=datetime.now(),
            event_type="test_event",
            source_ip="192.168.1.100",
            username="testuser",
            hostname="testhost",
            details="Test event details",
            severity="medium",
            log_source="/var/log/test.log"
        )
        
        self.db.add_event(event)
        
        # Verify event was added
        events = self.db.get_recent_events(1)
        assert len(events) == 1
        assert events[0].event_type == "test_event"
        assert events[0].source_ip == "192.168.1.100"
    
    def test_ip_reputation_update(self):
        """Test IP reputation tracking"""
        self.db.update_ip_reputation("192.168.1.100", "high")
        self.db.update_ip_reputation("192.168.1.100", "critical")
        
        # Check reputation was updated
        conn = sqlite3.connect(self.temp_db.name)
        cursor = conn.cursor()
        cursor.execute("SELECT reputation_score FROM ip_reputation WHERE ip_address = ?", 
                      ("192.168.1.100",))
        score = cursor.fetchone()[0]
        conn.close()
        
        assert score == 30  # high (10) + critical (20)
    
    def test_cleanup_old_events(self):
        """Test cleanup of old events"""
        # Add old event
        old_event = SecurityEvent(
            timestamp=datetime.now() - timedelta(days=35),
            event_type="old_event",
            source_ip="192.168.1.100",
            username="testuser",
            hostname="testhost",
            details="Old event",
            severity="low",
            log_source="/var/log/test.log"
        )
        self.db.add_event(old_event)
        
        # Add recent event
        recent_event = SecurityEvent(
            timestamp=datetime.now(),
            event_type="recent_event",
            source_ip="192.168.1.101",
            username="testuser",
            hostname="testhost",
            details="Recent event",
            severity="low",
            log_source="/var/log/test.log"
        )
        self.db.add_event(recent_event)
        
        # Cleanup events older than 30 days
        deleted = self.db.cleanup_old_events(30)
        assert deleted == 1
        
        # Verify only recent event remains
        events = self.db.get_recent_events(24)
        assert len(events) == 1
        assert events[0].event_type == "recent_event"


class TestLogPatternMatcher:
    """Test LogPatternMatcher functionality"""
    
    def setup_method(self):
        """Setup pattern matcher"""
        self.matcher = LogPatternMatcher()
    
    def test_ssh_failed_login_pattern(self):
        """Test SSH failed login pattern matching"""
        log_line = "Failed password for admin from 192.168.1.100 port 22 ssh2"
        events = self.matcher.match_patterns(log_line, "/var/log/auth.log")
        
        assert len(events) == 1
        assert events[0].event_type == "ssh_failed_login"
        assert events[0].source_ip == "192.168.1.100"
        assert events[0].username == "admin"
        assert events[0].severity == "medium"
    
    def test_ssh_invalid_user_pattern(self):
        """Test SSH invalid user pattern matching"""
        log_line = "Invalid user hacker from 10.0.0.1 port 22"
        events = self.matcher.match_patterns(log_line, "/var/log/auth.log")
        
        assert len(events) == 1
        assert events[0].event_type == "ssh_invalid_user"
        assert events[0].source_ip == "10.0.0.1"
        assert events[0].username == "hacker"
        assert events[0].severity == "high"
    
    def test_sql_injection_pattern(self):
        """Test SQL injection pattern matching"""
        log_line = "192.168.1.50 - - [01/Jan/2025:12:00:00] \"GET /search?q='; DROP TABLE users; --\" 200"
        events = self.matcher.match_patterns(log_line, "/var/log/apache2/access.log")

        # This log line matches both SQL injection and command injection patterns
        assert len(events) >= 1

        # Check that SQL injection is detected
        sql_events = [e for e in events if e.event_type == "sql_injection_attempt"]
        assert len(sql_events) == 1
        assert sql_events[0].source_ip == "192.168.1.50"
        assert sql_events[0].severity == "critical"
    
    def test_no_pattern_match(self):
        """Test log line with no pattern matches"""
        log_line = "Normal system startup message"
        events = self.matcher.match_patterns(log_line, "/var/log/syslog")
        
        assert len(events) == 0
    
    def test_custom_pattern_addition(self):
        """Test adding custom threat patterns"""
        custom_pattern = ThreatPattern(
            name="Custom Test Pattern",
            description="Test pattern for unit tests",
            regex_pattern=r"CUSTOM_THREAT from (?P<ip>\d+\.\d+\.\d+\.\d+)",
            severity="high"
        )
        
        self.matcher.add_custom_pattern(custom_pattern)
        
        log_line = "CUSTOM_THREAT from 192.168.1.200"
        events = self.matcher.match_patterns(log_line, "/var/log/test.log")
        
        assert len(events) == 1
        assert events[0].event_type == "custom_test_pattern"
        assert events[0].source_ip == "192.168.1.200"
        assert events[0].severity == "high"
    
    def test_pattern_enable_disable(self):
        """Test enabling and disabling patterns"""
        # Disable SSH failed login pattern
        self.matcher.disable_pattern("SSH Failed Login")
        
        log_line = "Failed password for admin from 192.168.1.100 port 22 ssh2"
        events = self.matcher.match_patterns(log_line, "/var/log/auth.log")
        
        assert len(events) == 0  # Pattern should be disabled
        
        # Re-enable pattern
        self.matcher.enable_pattern("SSH Failed Login")
        events = self.matcher.match_patterns(log_line, "/var/log/auth.log")
        
        assert len(events) == 1  # Pattern should work again


class TestThreatAnalyzer:
    """Test ThreatAnalyzer functionality"""
    
    def setup_method(self):
        """Setup threat analyzer"""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.temp_db.close()
        self.db = SecurityDatabase(self.temp_db.name)
        self.analyzer = ThreatAnalyzer(self.db)
    
    def teardown_method(self):
        """Cleanup test database"""
        Path(self.temp_db.name).unlink(missing_ok=True)
    
    def test_basic_analysis(self):
        """Test basic event analysis"""
        events = [
            SecurityEvent(
                timestamp=datetime.now(),
                event_type="ssh_failed_login",
                source_ip="192.168.1.100",
                username="admin",
                hostname="testhost",
                details="Failed login attempt",
                severity="medium",
                log_source="/var/log/auth.log"
            ),
            SecurityEvent(
                timestamp=datetime.now(),
                event_type="sql_injection_attempt",
                source_ip="10.0.0.1",
                username="",
                hostname="testhost",
                details="SQL injection detected",
                severity="critical",
                log_source="/var/log/apache2/access.log"
            )
        ]
        
        analysis = self.analyzer.analyze_events(events)
        
        assert analysis['total_events'] == 2
        assert analysis['severity_breakdown']['medium'] == 1
        assert analysis['severity_breakdown']['critical'] == 1
        assert analysis['top_source_ips']['192.168.1.100'] == 1
        assert analysis['top_source_ips']['10.0.0.1'] == 1
        assert analysis['threat_score'] > 0
    
    def test_brute_force_detection(self):
        """Test brute force attack detection"""
        base_time = datetime.now()
        events = []
        
        # Create 10 failed login attempts from same IP within 5 minutes
        for i in range(10):
            events.append(SecurityEvent(
                timestamp=base_time + timedelta(seconds=i * 30),
                event_type="ssh_failed_login",
                source_ip="192.168.1.100",
                username=f"user{i}",
                hostname="testhost",
                details=f"Failed login attempt {i}",
                severity="medium",
                log_source="/var/log/auth.log"
            ))
        
        analysis = self.analyzer.analyze_events(events)
        
        assert len(analysis['brute_force_attempts']) == 1
        attack = analysis['brute_force_attempts'][0]
        assert attack['source_ip'] == "192.168.1.100"
        assert attack['attempt_count'] == 10
        assert attack['severity'] in ['high', 'critical']
    
    def test_threat_score_calculation(self):
        """Test threat score calculation"""
        # Test with no events
        analysis = self.analyzer.analyze_events([])
        assert analysis['threat_score'] == 0
        
        # Test with critical events
        critical_events = [
            SecurityEvent(
                timestamp=datetime.now(),
                event_type="sql_injection_attempt",
                source_ip="10.0.0.1",
                username="",
                hostname="testhost",
                details="Critical security event",
                severity="critical",
                log_source="/var/log/test.log"
            )
        ]
        
        analysis = self.analyzer.analyze_events(critical_events)
        assert analysis['threat_score'] > 20  # Should have significant score
    
    def test_recommendations_generation(self):
        """Test security recommendations generation"""
        # Create events that should trigger recommendations
        events = []
        
        # Add many events to trigger high volume recommendation
        for i in range(150):
            events.append(SecurityEvent(
                timestamp=datetime.now(),
                event_type="ssh_failed_login",
                source_ip="192.168.1.100",
                username="admin",
                hostname="testhost",
                details=f"Failed login {i}",
                severity="medium",
                log_source="/var/log/auth.log"
            ))
        
        analysis = self.analyzer.analyze_events(events)
        recommendations = analysis['recommendations']
        
        assert len(recommendations) > 0
        # Should recommend rate limiting due to high event count
        assert any("rate limiting" in rec.lower() for rec in recommendations)
    
    def test_ip_analysis(self):
        """Test specific IP analysis"""
        # Add events for specific IP
        events = [
            SecurityEvent(
                timestamp=datetime.now(),
                event_type="ssh_failed_login",
                source_ip="192.168.1.100",
                username="admin",
                hostname="testhost",
                details="Failed login",
                severity="medium",
                log_source="/var/log/auth.log"
            )
        ]
        
        for event in events:
            self.db.add_event(event)
        
        analysis = self.analyzer.get_ip_analysis("192.168.1.100", 24)
        
        assert analysis['ip'] == "192.168.1.100"
        assert analysis['total_events'] == 1
        assert analysis['threat_level'] == 'low'  # Single event = low threat
        assert 'admin' in analysis['usernames_targeted']


if __name__ == "__main__":
    pytest.main([__file__])
