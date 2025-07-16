#!/usr/bin/env python3
"""
SecurityWatch Pro - Command Line Interface
Professional security monitoring with intelligent pattern recognition, automated threat detection,
and comprehensive reporting for Windows, Linux, and macOS systems.
"""

import argparse
import sys
import time
import signal
from pathlib import Path

# Add the securitywatch package to the path
sys.path.insert(0, str(Path(__file__).parent))

from securitywatch import (
    SecurityWatchMonitor, SecurityWatchConfig, SecurityDatabase,
    ThreatAnalyzer, LogPatternMatcher
)
from securitywatch.core.reports import ReportGenerator
from securitywatch.core.alerts import AlertManager

__version__ = "1.0.0"


class SecurityWatchCLI:
    """Command Line Interface for SecurityWatch Pro"""
    
    def __init__(self):
        self.config = SecurityWatchConfig()
        self.monitor = SecurityWatchMonitor(self.config)
        self.database = SecurityDatabase()
        self.report_generator = ReportGenerator(self.database)
        self.running = False
    
    def start_monitoring(self, daemon: bool = False):
        """Start security monitoring"""
        print("🛡️ SecurityWatch Pro v{} - Starting Security Monitoring".format(__version__))
        print("=" * 60)
        
        # Display configuration
        status = self.monitor.get_status()
        print(f"📁 Monitoring {status['log_files_monitored']} log files")
        print(f"📊 Total events in database: {status['total_events']}")
        
        if self.config.email.enabled:
            print(f"📧 Email alerts: Enabled ({len(self.config.email.to_emails)} recipients)")
        else:
            print("📧 Email alerts: Disabled")
        
        print(f"⏱️  Check interval: {self.config.monitoring.check_interval} seconds")
        print("=" * 60)
        
        # Setup signal handlers for graceful shutdown
        def signal_handler(signum, frame):
            print("\n🛑 Shutting down SecurityWatch Pro...")
            self.monitor.stop_monitoring()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Start monitoring
        self.monitor.start_monitoring()
        self.running = True
        
        if daemon:
            print("🔄 Running in daemon mode. Press Ctrl+C to stop.")
            try:
                while self.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
        else:
            print("✅ Monitoring started. Use 'stop' command to stop monitoring.")
    
    def stop_monitoring(self):
        """Stop security monitoring"""
        print("🛑 Stopping SecurityWatch Pro monitoring...")
        self.monitor.stop_monitoring()
        self.running = False
        print("✅ Monitoring stopped.")
    
    def show_status(self):
        """Show current monitoring status"""
        status = self.monitor.get_status()
        
        print("🛡️ SecurityWatch Pro Status")
        print("=" * 40)
        print(f"Status: {'🟢 Running' if status['running'] else '🔴 Stopped'}")
        print(f"Log Files: {status['log_files_monitored']}")
        print(f"Total Events: {status['total_events']}")
        
        if status['events_by_severity']:
            print("\nEvents by Severity:")
            for severity, count in status['events_by_severity'].items():
                print(f"  {severity.upper()}: {count}")
        
        if status['top_attacking_ips']:
            print("\nTop Attacking IPs:")
            for ip, count in status['top_attacking_ips']:
                print(f"  {ip}: {count} events")
    
    def run_scan(self):
        """Run manual security scan"""
        print("🔍 Running manual security scan...")
        result = self.monitor.run_manual_scan()
        
        print(f"✅ Scan completed. Found {result['events_found']} security events")
        
        if result['events_found'] > 0:
            analysis = result['analysis']
            print(f"🎯 Threat Score: {analysis['threat_score']}/100")
            print(f"🚨 Brute Force Attacks: {len(analysis['brute_force_attempts'])}")
            
            if analysis['recommendations']:
                print("\n💡 Recommendations:")
                for rec in analysis['recommendations'][:3]:
                    print(f"  • {rec}")
    
    def generate_report(self, report_type: str = 'html', hours: int = 24, 
                       output: str = None):
        """Generate security report"""
        print(f"📊 Generating {report_type.upper()} report for last {hours} hours...")
        
        try:
            if output:
                file_path = self.report_generator.save_report(report_type, hours, output)
            else:
                file_path = self.report_generator.save_report(report_type, hours)
            
            print(f"✅ Report saved to: {file_path}")
            
            # Show summary
            if report_type == 'json':
                report_data = self.report_generator.generate_json_report(hours)
                summary = report_data['summary']
                print(f"📈 Summary: {summary['total_events']} events, "
                      f"Threat Score: {summary['threat_score']}/100")
            
        except Exception as e:
            print(f"❌ Error generating report: {e}")
    
    def analyze_ip(self, ip_address: str, hours: int = 24):
        """Analyze specific IP address"""
        print(f"🔍 Analyzing IP address: {ip_address}")
        
        analysis = self.monitor.analyze_ip(ip_address, hours)
        
        if analysis['total_events'] == 0:
            print("✅ No recent activity from this IP address")
            return
        
        print(f"📊 Total Events: {analysis['total_events']}")
        print(f"🎯 Threat Level: {analysis['threat_level'].upper()}")
        print(f"⏰ First Seen: {analysis['first_seen']}")
        print(f"⏰ Last Seen: {analysis['last_seen']}")
        
        if analysis['usernames_targeted']:
            print(f"👤 Usernames Targeted: {', '.join(analysis['usernames_targeted'][:5])}")
        
        if analysis['is_brute_force']:
            print("🚨 WARNING: This IP shows brute force attack patterns!")
    
    def configure_email(self, smtp_server: str, smtp_port: int, username: str,
                       password: str, from_email: str, to_emails: list):
        """Configure email alerts"""
        print("📧 Configuring email alerts...")
        
        self.config.update_email_config(
            smtp_server, smtp_port, username, password, from_email, to_emails
        )
        
        print("✅ Email configuration saved")
        
        # Test email
        alert_manager = AlertManager(self.config)
        if alert_manager.send_test_alert():
            print("✅ Test email sent successfully")
        else:
            print("❌ Failed to send test email")
    
    def add_log_file(self, log_path: str):
        """Add log file to monitoring"""
        if self.monitor.add_log_file(log_path):
            print(f"✅ Added log file: {log_path}")
        else:
            print(f"❌ Failed to add log file: {log_path}")
    
    def list_log_files(self):
        """List monitored log files"""
        print("📁 Monitored Log Files:")
        for i, log_path in enumerate(self.config.monitoring.log_paths, 1):
            exists = "✅" if Path(log_path).exists() else "❌"
            print(f"  {i}. {exists} {log_path}")
    
    def show_recent_events(self, hours: int = 1, limit: int = 10):
        """Show recent security events"""
        events = self.monitor.get_recent_events(hours)
        
        if not events:
            print(f"✅ No security events in the last {hours} hour(s)")
            return
        
        print(f"🚨 Recent Security Events (last {hours} hour(s)):")
        print("=" * 80)
        
        for event in events[:limit]:
            severity_icon = {
                'critical': '🔥',
                'high': '⚠️',
                'medium': '📊',
                'low': '📝'
            }.get(event.severity, '📝')
            
            print(f"{severity_icon} {event.timestamp.strftime('%H:%M:%S')} | "
                  f"{event.event_type.replace('_', ' ').title()} | "
                  f"IP: {event.source_ip or 'Unknown'} | "
                  f"User: {event.username or 'Unknown'}")
        
        if len(events) > limit:
            print(f"... and {len(events) - limit} more events")


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="SecurityWatch Pro - Advanced Security Monitoring",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s start --daemon          Start monitoring in daemon mode
  %(prog)s scan                    Run manual security scan
  %(prog)s report --hours 24       Generate 24-hour HTML report
  %(prog)s analyze-ip 192.168.1.100  Analyze specific IP address
  %(prog)s events --hours 1        Show events from last hour
        """
    )
    
    parser.add_argument('--version', action='version', version=f'SecurityWatch Pro {__version__}')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Start command
    start_parser = subparsers.add_parser('start', help='Start security monitoring')
    start_parser.add_argument('--daemon', action='store_true', 
                             help='Run in daemon mode')
    
    # Stop command
    subparsers.add_parser('stop', help='Stop security monitoring')
    
    # Status command
    subparsers.add_parser('status', help='Show monitoring status')
    
    # Scan command
    subparsers.add_parser('scan', help='Run manual security scan')
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate security report')
    report_parser.add_argument('--type', choices=['html', 'json'], default='html',
                              help='Report format (default: html)')
    report_parser.add_argument('--hours', type=int, default=24,
                              help='Analysis period in hours (default: 24)')
    report_parser.add_argument('--output', help='Output filename')
    
    # Analyze IP command
    analyze_parser = subparsers.add_parser('analyze-ip', help='Analyze specific IP address')
    analyze_parser.add_argument('ip', help='IP address to analyze')
    analyze_parser.add_argument('--hours', type=int, default=24,
                               help='Analysis period in hours (default: 24)')
    
    # Events command
    events_parser = subparsers.add_parser('events', help='Show recent security events')
    events_parser.add_argument('--hours', type=int, default=1,
                              help='Time period in hours (default: 1)')
    events_parser.add_argument('--limit', type=int, default=10,
                              help='Maximum number of events to show (default: 10)')
    
    # Log files command
    subparsers.add_parser('logs', help='List monitored log files')
    
    # Add log command
    add_log_parser = subparsers.add_parser('add-log', help='Add log file to monitoring')
    add_log_parser.add_argument('path', help='Path to log file')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize CLI
    cli = SecurityWatchCLI()
    
    # Execute command
    try:
        if args.command == 'start':
            cli.start_monitoring(args.daemon)
        elif args.command == 'stop':
            cli.stop_monitoring()
        elif args.command == 'status':
            cli.show_status()
        elif args.command == 'scan':
            cli.run_scan()
        elif args.command == 'report':
            cli.generate_report(args.type, args.hours, args.output)
        elif args.command == 'analyze-ip':
            cli.analyze_ip(args.ip, args.hours)
        elif args.command == 'events':
            cli.show_recent_events(args.hours, args.limit)
        elif args.command == 'logs':
            cli.list_log_files()
        elif args.command == 'add-log':
            cli.add_log_file(args.path)
    
    except KeyboardInterrupt:
        print("\n🛑 Operation cancelled by user")
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
