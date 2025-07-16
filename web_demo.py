#!/usr/bin/env python3
"""
SecurityWatch Pro - Web Dashboard Demo
Demonstrates the beautiful web interface with sample data
"""

import sys
import time
import threading
from pathlib import Path
from datetime import datetime, timedelta

# Add the securitywatch package to the path
sys.path.insert(0, str(Path(__file__).parent))

from securitywatch import SecurityEvent, SecurityDatabase, ThreatAnalyzer
from securitywatch.web.app import create_app


def create_sample_data():
    """Create sample security events for demonstration"""
    print("📊 Creating sample security data...")
    
    # Create temporary database
    db = SecurityDatabase("demo_security.db")
    
    # Sample events for demonstration
    base_time = datetime.now()
    sample_events = []
    
    # Simulate brute force attack
    for i in range(20):
        sample_events.append(SecurityEvent(
            timestamp=base_time - timedelta(minutes=i*2),
            event_type="ssh_failed_login",
            source_ip="192.168.1.100",
            username=f"admin" if i % 3 == 0 else f"user{i % 5}",
            hostname="server01",
            details=f"Failed SSH login attempt #{i+1}",
            severity="medium",
            log_source="/var/log/auth.log"
        ))
    
    # Add some critical events
    sample_events.extend([
        SecurityEvent(
            timestamp=base_time - timedelta(minutes=30),
            event_type="sql_injection_attempt",
            source_ip="10.0.0.50",
            username="",
            hostname="webserver",
            details="SQL injection detected: '; DROP TABLE users; --",
            severity="critical",
            log_source="/var/log/apache2/access.log"
        ),
        SecurityEvent(
            timestamp=base_time - timedelta(minutes=45),
            event_type="privilege_escalation",
            source_ip="192.168.1.200",
            username="hacker",
            hostname="server02",
            details="Attempted sudo privilege escalation",
            severity="high",
            log_source="/var/log/secure"
        ),
        SecurityEvent(
            timestamp=base_time - timedelta(minutes=60),
            event_type="failed_root_login",
            source_ip="203.0.113.10",
            username="root",
            hostname="server01",
            details="Failed root login from external IP",
            severity="critical",
            log_source="/var/log/auth.log"
        )
    ])
    
    # Add events to database
    for event in sample_events:
        db.add_event(event)
        db.update_ip_reputation(event.source_ip, event.severity)
    
    print(f"✅ Created {len(sample_events)} sample security events")
    return db


def run_web_demo():
    """Run the web dashboard demo"""
    print("🛡️ SecurityWatch Pro - Web Dashboard Demo")
    print("=" * 60)
    
    # Create sample data
    db = create_sample_data()
    
    # Create web application
    print("🌐 Starting web dashboard...")
    app, socketio = create_app()
    
    # Override database in app config
    app.config['DATABASE'] = db
    app.config['ANALYZER'] = ThreatAnalyzer(db)
    
    print()
    print("🎉 SecurityWatch Pro Web Dashboard is now running!")
    print("=" * 60)
    print("🔗 Access the dashboard at: http://localhost:5000")
    print()
    print("📊 Demo Features Available:")
    print("  • Real-time threat monitoring dashboard")
    print("  • Interactive charts and graphs")
    print("  • Live threat feed with sample attacks")
    print("  • Brute force attack detection")
    print("  • IP analysis and reputation tracking")
    print("  • Professional HTML/JSON reports")
    print("  • Configuration management interface")
    print("  • Mobile-responsive design")
    print()
    print("🎯 Sample Data Includes:")
    print("  • 20 SSH brute force attempts from 192.168.1.100")
    print("  • SQL injection attack from 10.0.0.50")
    print("  • Privilege escalation attempt")
    print("  • Failed root login from external IP")
    print()
    print("🚀 Press Ctrl+C to stop the demo")
    print("=" * 60)
    
    try:
        # Start the web server
        socketio.run(app, host='0.0.0.0', port=5000, debug=False)
    except KeyboardInterrupt:
        print("\n🛑 Demo stopped by user")
    finally:
        # Cleanup demo database
        Path("demo_security.db").unlink(missing_ok=True)
        print("🧹 Demo data cleaned up")


if __name__ == "__main__":
    run_web_demo()
