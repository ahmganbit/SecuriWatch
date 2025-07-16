#!/usr/bin/env python3
"""
SecurityWatch Pro - AI/ML Demo
Demonstrates the AI-powered threat detection capabilities
"""

import sys
import time
import random
from pathlib import Path
from datetime import datetime, timedelta

# Add the securitywatch package to the path
sys.path.insert(0, str(Path(__file__).parent))

from securitywatch import SecurityEvent, SecurityDatabase, ThreatAnalyzer
from securitywatch.ai.ml_models import MLModelManager


def create_ai_demo_data():
    """Create comprehensive demo data for AI analysis"""
    print("🤖 Creating AI demo data with sophisticated attack patterns...")
    
    # Create temporary database
    db = SecurityDatabase("ai_demo_security.db")
    
    base_time = datetime.now()
    events = []
    
    # 1. Sophisticated Brute Force Attack with AI Patterns
    print("   📊 Generating brute force attack patterns...")
    attacker_ip = "203.0.113.50"
    for i in range(100):
        # Automated timing pattern (every 3-5 seconds)
        time_offset = i * random.uniform(3, 5)
        timestamp = base_time - timedelta(seconds=time_offset)
        
        # Progressive username enumeration
        usernames = ["admin", "root", "administrator", "user", "test", "guest", "service"]
        username = usernames[i % len(usernames)]
        
        events.append(SecurityEvent(
            timestamp=timestamp,
            event_type="ssh_failed_login",
            source_ip=attacker_ip,
            username=username,
            hostname="server01",
            details=f"SSH login failure for {username} from {attacker_ip}",
            severity="medium",
            log_source="/var/log/auth.log"
        ))
    
    # 2. Advanced Persistent Threat (APT) Simulation
    print("   🎯 Generating APT-style attack patterns...")
    apt_ip = "192.168.100.200"
    apt_events = [
        ("reconnaissance", "Port scan detected", "low"),
        ("initial_access", "Successful login after hours", "medium"),
        ("privilege_escalation", "Sudo command execution", "high"),
        ("lateral_movement", "SMB connection to multiple hosts", "high"),
        ("data_exfiltration", "Large data transfer detected", "critical"),
        ("persistence", "Scheduled task created", "high")
    ]
    
    for i, (event_type, details, severity) in enumerate(apt_events):
        timestamp = base_time - timedelta(hours=24-i*2)  # Spread over 24 hours
        events.append(SecurityEvent(
            timestamp=timestamp,
            event_type=event_type,
            source_ip=apt_ip,
            username="compromised_user",
            hostname="workstation05",
            details=details,
            severity=severity,
            log_source="/var/log/security.log"
        ))
    
    # 3. Insider Threat Behavioral Anomaly
    print("   👤 Generating insider threat patterns...")
    insider_events = []
    for day in range(7):
        # Normal business hours activity
        for hour in [9, 10, 14, 16]:
            timestamp = base_time - timedelta(days=day, hours=hour)
            insider_events.append(SecurityEvent(
                timestamp=timestamp,
                event_type="file_access",
                source_ip="192.168.1.150",
                username="john.doe",
                hostname="workstation10",
                details="Accessed customer database",
                severity="low",
                log_source="/var/log/audit.log"
            ))
        
        # Anomalous off-hours activity (day 6)
        if day == 6:
            for hour in [22, 23, 1, 2]:
                timestamp = base_time - timedelta(days=day, hours=hour)
                insider_events.append(SecurityEvent(
                    timestamp=timestamp,
                    event_type="sensitive_file_access",
                    source_ip="192.168.1.150",
                    username="john.doe",
                    hostname="workstation10",
                    details="Accessed confidential financial records",
                    severity="high",
                    log_source="/var/log/audit.log"
                ))
    
    events.extend(insider_events)
    
    # 4. Malware Command & Control Communication
    print("   🦠 Generating malware C&C patterns...")
    malware_ips = ["198.51.100.10", "198.51.100.11", "198.51.100.12"]
    for i in range(50):
        timestamp = base_time - timedelta(minutes=i*10)
        malware_ip = random.choice(malware_ips)
        
        events.append(SecurityEvent(
            timestamp=timestamp,
            event_type="suspicious_network_connection",
            source_ip="192.168.1.75",
            username="",
            hostname="infected_host",
            details=f"Outbound connection to known C&C server {malware_ip}",
            severity="critical",
            log_source="/var/log/firewall.log"
        ))
    
    # 5. SQL Injection Attack Sequence
    print("   💉 Generating SQL injection attack patterns...")
    web_attacker = "203.0.113.100"
    sql_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT * FROM passwords --",
        "'; INSERT INTO admin VALUES('hacker','password'); --"
    ]
    
    for i, payload in enumerate(sql_payloads * 5):
        timestamp = base_time - timedelta(minutes=i*2)
        events.append(SecurityEvent(
            timestamp=timestamp,
            event_type="sql_injection_attempt",
            source_ip=web_attacker,
            username="",
            hostname="webserver",
            details=f"SQL injection detected: {payload}",
            severity="critical",
            log_source="/var/log/apache2/error.log"
        ))
    
    # Add all events to database
    for event in events:
        db.add_event(event)
        db.update_ip_reputation(event.source_ip, event.severity)
    
    print(f"✅ Created {len(events)} sophisticated security events for AI analysis")
    return db


def run_ai_demo():
    """Run comprehensive AI demo"""
    print("🤖 SecurityWatch Pro - AI/ML Threat Detection Demo")
    print("=" * 70)
    
    # Create demo data
    db = create_ai_demo_data()
    
    # Initialize AI-powered analyzer
    print("\n🧠 Initializing AI-powered threat analyzer...")
    analyzer = ThreatAnalyzer(db, enable_ai=True)
    
    if not analyzer.enable_ai:
        print("❌ AI components not available. Please install AI dependencies:")
        print("   pip install scikit-learn numpy pandas joblib")
        return
    
    # Train AI models
    print("\n📚 Training AI models on demo data...")
    training_result = analyzer.train_ai_models()
    
    if training_result.get('overall_success'):
        print("✅ AI models trained successfully!")
        
        # Show training summary
        models_trained = training_result.get('models_trained', {})
        for model_name, result in models_trained.items():
            status = "✅" if result.get('success') else "❌"
            print(f"   {status} {model_name.replace('_', ' ').title()}")
    else:
        print("⚠️ Some AI models failed to train, but demo will continue...")
    
    # Get recent events for analysis
    print("\n🔍 Running comprehensive AI analysis...")
    recent_events = db.get_recent_events(48)  # Last 48 hours
    
    # Run AI-powered analysis
    ai_analysis = analyzer.analyze_events_comprehensive_ai(recent_events)
    
    # Display results
    print("\n" + "=" * 70)
    print("🎯 AI THREAT ANALYSIS RESULTS")
    print("=" * 70)
    
    # Overall insights
    insights = ai_analysis.get('insights', {})
    if insights:
        print(f"\n🚨 Overall Threat Level: {insights.get('overall_threat_level', 'unknown').upper()}")
        print(f"🎯 Confidence Score: {insights.get('confidence_score', 0):.1f}%")
        
        # Key findings
        key_findings = insights.get('key_findings', [])
        if key_findings:
            print(f"\n🔍 Key AI Findings:")
            for finding in key_findings:
                print(f"   • {finding}")
        
        # Risk factors
        risk_factors = insights.get('risk_factors', [])
        if risk_factors:
            print(f"\n⚠️ Risk Factors Identified:")
            for risk in risk_factors:
                print(f"   • {risk}")
        
        # Recommendations
        recommendations = insights.get('recommendations', [])
        if recommendations:
            print(f"\n💡 AI Recommendations:")
            for rec in recommendations:
                print(f"   • {rec}")
    
    # Anomaly detection results
    anomaly_results = ai_analysis.get('anomaly_detection', {})
    if anomaly_results:
        anomalies = anomaly_results.get('anomalies', [])
        print(f"\n🔍 Anomaly Detection: {len(anomalies)} anomalies detected")
        
        for anomaly in anomalies[:3]:  # Show top 3
            print(f"   🚨 {anomaly.get('anomaly_type', 'Unknown')}: {anomaly.get('description', 'No description')}")
            print(f"      Confidence: {anomaly.get('confidence', 0):.1f}% | Severity: {anomaly.get('severity', 'unknown')}")
    
    # Threat classification results
    threat_results = ai_analysis.get('threat_classification', {})
    if threat_results:
        classifications = threat_results.get('classifications', [])
        print(f"\n🎯 Threat Classification: {len(classifications)} threats classified")
        
        for classification in classifications[:3]:  # Show top 3
            print(f"   ⚔️ {classification.get('predicted_threat_type', 'Unknown')}")
            print(f"      Risk Score: {classification.get('risk_score', 0):.1f} | Confidence: {classification.get('threat_confidence', 0):.1f}%")
    
    # Behavioral analysis results
    behavioral_results = ai_analysis.get('behavioral_analysis', {})
    if behavioral_results:
        behavioral_anomalies = behavioral_results.get('anomalies', [])
        print(f"\n👤 Behavioral Analysis: {len(behavioral_anomalies)} behavioral anomalies detected")
        
        for anomaly in behavioral_anomalies[:3]:  # Show top 3
            print(f"   🔍 {anomaly.get('type', 'Unknown')}: {anomaly.get('description', 'No description')}")
            print(f"      Entity: {anomaly.get('entity', 'unknown')} | Severity: {anomaly.get('severity', 'unknown')}")
    
    # Predictive analysis
    print("\n🔮 Running predictive threat analysis...")
    predictions = analyzer.predict_threats(24)
    
    if predictions and 'summary' in predictions:
        summary = predictions['summary']
        print(f"\n🔮 Threat Predictions (Next 24 Hours):")
        print(f"   📊 Total Predicted Events: {summary.get('total_predicted_events', 0)}")
        print(f"   📈 Average Severity Score: {summary.get('average_severity_score', 0):.1f}")
        
        alerts = summary.get('alerts', [])
        if alerts:
            print(f"\n⚠️ Predictive Alerts:")
            for alert in alerts:
                print(f"   • {alert}")
        
        pred_recommendations = summary.get('recommendations', [])
        if pred_recommendations:
            print(f"\n💡 Predictive Recommendations:")
            for rec in pred_recommendations:
                print(f"   • {rec}")
    
    # AI Model Status
    print("\n" + "=" * 70)
    print("🤖 AI MODEL STATUS")
    print("=" * 70)
    
    ai_status = analyzer.get_ai_status()
    if ai_status.get('ai_enabled'):
        print("✅ AI System: OPERATIONAL")
        
        models = ['anomaly_detector', 'threat_classifier', 'behavioral_analyzer', 'predictive_engine']
        for model in models:
            model_info = ai_status.get(model, {})
            if model == 'behavioral_analyzer':
                status = "✅ READY"  # Always ready
            else:
                status = "✅ TRAINED" if model_info.get('is_trained') else "⚠️ NEEDS TRAINING"
            print(f"   {model.replace('_', ' ').title()}: {status}")
    else:
        print("❌ AI System: NOT AVAILABLE")
    
    print("\n" + "=" * 70)
    print("🎉 AI DEMO COMPLETED!")
    print("=" * 70)
    print("🌐 Launch the web dashboard to see the AI interface:")
    print("   python web_server.py")
    print("   Then visit: http://localhost:5000/ai")
    print("\n🧹 Demo database will be cleaned up on exit...")
    
    # Cleanup
    Path("ai_demo_security.db").unlink(missing_ok=True)


if __name__ == "__main__":
    try:
        run_ai_demo()
    except KeyboardInterrupt:
        print("\n🛑 Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Cleanup
        Path("ai_demo_security.db").unlink(missing_ok=True)
        print("🧹 Cleanup completed")
