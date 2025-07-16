#!/usr/bin/env python3
"""
SecurityWatch Pro - Demo Script
Demonstrates the core functionality of SecurityWatch Pro
"""

import sys
import tempfile
from pathlib import Path
from datetime import datetime

# Add the securitywatch package to the path
sys.path.insert(0, str(Path(__file__).parent))

from securitywatch import (
    SecurityWatchMonitor, SecurityWatchConfig, SecurityDatabase,
    ThreatAnalyzer, LogPatternMatcher, SecurityEvent
)
from securitywatch.core.reports import ReportGenerator


def demo_pattern_matching():
    """Demonstrate pattern matching capabilities"""
    print("🔍 Demo: Pattern Matching")
    print("=" * 40)
    
    matcher = LogPatternMatcher()
    
    # Test various attack patterns
    test_logs = [
        "Failed password for admin from 192.168.1.100 port 22 ssh2",
        "Invalid user hacker from 10.0.0.1 port 22",
        "192.168.1.50 - - [01/Jan/2025:12:00:00] \"GET /search?q='; DROP TABLE users; --\" 200",
        "sudo: authentication failure; logname=user uid=1000 euid=0 tty=/dev/pts/0 ruser=user rhost=192.168.1.200 user=user",
        "Failed password for root from 203.0.113.10 port 22 ssh2"
    ]
    
    for log_line in test_logs:
        events = matcher.match_patterns(log_line, "/var/log/test.log")
        if events:
            for event in events:
                severity_icon = {
                    'critical': '🔥',
                    'high': '⚠️',
                    'medium': '📊',
                    'low': '📝'
                }.get(event.severity, '📝')
                
                print(f"{severity_icon} {event.event_type.replace('_', ' ').title()}")
                print(f"   IP: {event.source_ip or 'Unknown'}")
                print(f"   User: {event.username or 'Unknown'}")
                print(f"   Severity: {event.severity.upper()}")
                print()
        else:
            print(f"✅ No threats detected in: {log_line[:50]}...")
            print()


def demo_threat_analysis():
    """Demonstrate threat analysis capabilities"""
    print("🎯 Demo: Threat Analysis")
    print("=" * 40)
    
    # Create temporary database
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp_db:
        db = SecurityDatabase(tmp_db.name)
        analyzer = ThreatAnalyzer(db)
        
        # Create sample security events
        events = []
        base_time = datetime.now()
        
        # Simulate brute force attack
        for i in range(15):
            events.append(SecurityEvent(
                timestamp=base_time,
                event_type="ssh_failed_login",
                source_ip="192.168.1.100",
                username=f"user{i % 3}",  # Targeting multiple users
                hostname="server01",
                details=f"Failed SSH login attempt {i}",
                severity="medium",
                log_source="/var/log/auth.log"
            ))
        
        # Add some critical events
        events.append(SecurityEvent(
            timestamp=base_time,
            event_type="sql_injection_attempt",
            source_ip="10.0.0.50",
            username="",
            hostname="webserver",
            details="SQL injection detected in web application",
            severity="critical",
            log_source="/var/log/apache2/access.log"
        ))
        
        # Analyze the events
        analysis = analyzer.analyze_events(events)
        
        print(f"📊 Total Events: {analysis['total_events']}")
        print(f"🎯 Threat Score: {analysis['threat_score']}/100")
        print(f"🚨 Brute Force Attacks: {len(analysis['brute_force_attempts'])}")
        
        print("\nSeverity Breakdown:")
        for severity, count in analysis['severity_breakdown'].items():
            print(f"  {severity.upper()}: {count}")
        
        print("\nTop Attacking IPs:")
        for ip, count in analysis['top_source_ips'].most_common(3):
            print(f"  {ip}: {count} events")
        
        if analysis['brute_force_attempts']:
            print("\n🚨 Brute Force Attack Details:")
            for attack in analysis['brute_force_attempts']:
                print(f"  IP: {attack['source_ip']}")
                print(f"  Attempts: {attack['attempt_count']}")
                print(f"  Severity: {attack['severity'].upper()}")
                print(f"  Users Targeted: {', '.join(attack['usernames_targeted'])}")
        
        print("\n💡 Security Recommendations:")
        for i, rec in enumerate(analysis['recommendations'][:3], 1):
            print(f"  {i}. {rec}")
        
        # Cleanup
        Path(tmp_db.name).unlink(missing_ok=True)


def demo_configuration():
    """Demonstrate configuration management"""
    print("⚙️ Demo: Configuration Management")
    print("=" * 40)
    
    # Create temporary config
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp_config:
        config = SecurityWatchConfig(tmp_config.name)
        
        print(f"📁 Log Files Detected: {len(config.monitoring.log_paths)}")
        for log_path in config.monitoring.log_paths[:3]:
            exists = "✅" if Path(log_path).exists() else "❌"
            print(f"  {exists} {log_path}")
        
        if len(config.monitoring.log_paths) > 3:
            print(f"  ... and {len(config.monitoring.log_paths) - 3} more")
        
        print(f"\n⏱️ Check Interval: {config.monitoring.check_interval} seconds")
        print(f"📧 Email Alerts: {'Enabled' if config.email.enabled else 'Disabled'}")
        print(f"🗄️ Database Retention: {config.monitoring.database_retention_days} days")
        
        # Cleanup
        Path(tmp_config.name).unlink(missing_ok=True)


def demo_reporting():
    """Demonstrate report generation"""
    print("📊 Demo: Report Generation")
    print("=" * 40)
    
    # Create temporary database with sample data
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp_db:
        db = SecurityDatabase(tmp_db.name)
        report_gen = ReportGenerator(db)
        
        # Add sample events
        sample_events = [
            SecurityEvent(
                timestamp=datetime.now(),
                event_type="ssh_failed_login",
                source_ip="192.168.1.100",
                username="admin",
                hostname="server01",
                details="Failed SSH login",
                severity="medium",
                log_source="/var/log/auth.log"
            ),
            SecurityEvent(
                timestamp=datetime.now(),
                event_type="sql_injection_attempt",
                source_ip="10.0.0.50",
                username="",
                hostname="webserver",
                details="SQL injection attempt",
                severity="critical",
                log_source="/var/log/apache2/access.log"
            )
        ]
        
        for event in sample_events:
            db.add_event(event)
        
        # Generate JSON report
        json_report = report_gen.generate_json_report(24)
        
        print("📄 JSON Report Generated:")
        print(f"  Total Events: {json_report['summary']['total_events']}")
        print(f"  Threat Score: {json_report['summary']['threat_score']}/100")
        print(f"  Critical Events: {json_report['summary']['severity_breakdown'].get('critical', 0)}")
        
        # Generate HTML report
        try:
            html_file = report_gen.save_report('html', 24)
            print(f"  HTML Report: {html_file}")
        except Exception as e:
            print(f"  HTML Report: Error - {e}")
        
        # Cleanup
        Path(tmp_db.name).unlink(missing_ok=True)


def main():
    """Run all demos"""
    print("🛡️ SecurityWatch Pro - Feature Demonstration")
    print("=" * 60)
    print()
    
    try:
        demo_pattern_matching()
        print()
        
        demo_threat_analysis()
        print()
        
        demo_configuration()
        print()
        
        demo_reporting()
        print()
        
        print("✅ All demos completed successfully!")
        print("🚀 SecurityWatch Pro is ready for use!")
        
    except Exception as e:
        print(f"❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
