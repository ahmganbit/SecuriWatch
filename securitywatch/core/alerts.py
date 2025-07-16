"""
SecurityWatch Pro - Alert Management System
"""

import smtplib
import logging
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict

from ..models.events import SecurityEvent
from ..config.settings import SecurityWatchConfig


class AlertManager:
    """Manages security alerts and notifications"""
    
    def __init__(self, config: SecurityWatchConfig):
        self.config = config
        self.logger = logging.getLogger('SecurityWatchPro.Alerts')
        self.last_alert_time = {}
        
    def process_events(self, events: List[SecurityEvent]):
        """Process events and send alerts if needed"""
        if not events:
            return
        
        # Filter events by severity threshold
        severity_levels = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        threshold = severity_levels.get(self.config.alerts.severity_threshold, 2)
        
        alert_events = [
            event for event in events 
            if severity_levels.get(event.severity, 1) >= threshold
        ]
        
        if not alert_events:
            return
        
        # Check if we should send alerts (rate limiting)
        now = datetime.now()
        last_alert = self.last_alert_time.get('general', datetime.min)
        
        if (now - last_alert).total_seconds() < (self.config.alerts.alert_frequency * 60):
            return  # Too soon since last alert
        
        # Send alerts
        if self.config.alerts.email_enabled and self.config.email.enabled:
            self._send_email_alert(alert_events)
        
        if self.config.alerts.console_enabled:
            self._send_console_alert(alert_events)
        
        if self.config.alerts.log_enabled:
            self._log_alert(alert_events)
        
        self.last_alert_time['general'] = now
    
    def _send_email_alert(self, events: List[SecurityEvent]):
        """Send email alert"""
        try:
            # Create email content
            subject = f"🚨 SecurityWatch Alert - {len(events)} Security Events Detected"
            body = self._create_email_body(events)
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.config.email.from_email
            msg['To'] = ', '.join(self.config.email.to_emails)
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            with smtplib.SMTP(self.config.email.smtp_server, self.config.email.smtp_port) as server:
                if self.config.email.use_tls:
                    server.starttls()
                
                if self.config.email.username and self.config.email.password:
                    server.login(self.config.email.username, self.config.email.password)
                
                server.send_message(msg)
            
            self.logger.info(f"Email alert sent to {len(self.config.email.to_emails)} recipients")
            
        except Exception as e:
            self.logger.error(f"Failed to send email alert: {e}")
    
    def _create_email_body(self, events: List[SecurityEvent]) -> str:
        """Create HTML email body"""
        # Group events by severity
        severity_groups = {'critical': [], 'high': [], 'medium': [], 'low': []}
        for event in events:
            severity_groups[event.severity].append(event)
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
                .header {{ background: #c0392b; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
                .summary {{ background: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .critical {{ background: #e74c3c; color: white; padding: 10px; margin: 5px 0; border-radius: 3px; }}
                .high {{ background: #f39c12; color: white; padding: 10px; margin: 5px 0; border-radius: 3px; }}
                .medium {{ background: #3498db; color: white; padding: 10px; margin: 5px 0; border-radius: 3px; }}
                .low {{ background: #95a5a6; color: white; padding: 10px; margin: 5px 0; border-radius: 3px; }}
                .event {{ margin: 5px 0; padding: 8px; border-left: 4px solid #ccc; background: #f9f9f9; }}
                .footer {{ background: #34495e; color: white; padding: 15px; border-radius: 5px; margin-top: 20px; text-align: center; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ SecurityWatch Pro Alert</h1>
                <p>Security Alert - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="summary">
                <h2>📊 Alert Summary</h2>
                <p><strong>Total Events:</strong> {len(events)}</p>
                <p><strong>Critical:</strong> {len(severity_groups['critical'])}</p>
                <p><strong>High:</strong> {len(severity_groups['high'])}</p>
                <p><strong>Medium:</strong> {len(severity_groups['medium'])}</p>
                <p><strong>Low:</strong> {len(severity_groups['low'])}</p>
            </div>
        """
        
        # Add events by severity
        for severity in ['critical', 'high', 'medium', 'low']:
            if severity_groups[severity]:
                html += f"""
                <div class="{severity}">
                    <h3>{severity.upper()} SEVERITY EVENTS ({len(severity_groups[severity])})</h3>
                </div>
                """
                
                for event in severity_groups[severity][:10]:  # Limit to 10 events per severity
                    html += f"""
                    <div class="event">
                        <strong>{event.event_type.replace('_', ' ').title()}</strong><br>
                        <strong>Source IP:</strong> {event.source_ip or 'Unknown'}<br>
                        <strong>Username:</strong> {event.username or 'Unknown'}<br>
                        <strong>Time:</strong> {event.timestamp.strftime('%Y-%m-%d %H:%M:%S')}<br>
                        <strong>Details:</strong> {event.details[:100]}{'...' if len(event.details) > 100 else ''}
                    </div>
                    """
                
                if len(severity_groups[severity]) > 10:
                    html += f"<p><em>... and {len(severity_groups[severity]) - 10} more {severity} events</em></p>"
        
        html += """
            <div class="footer">
                <p>This alert was generated by SecurityWatch Pro</p>
                <p>Please review your security logs and take appropriate action</p>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _send_console_alert(self, events: List[SecurityEvent]):
        """Send console alert"""
        print("\n" + "="*60)
        print("🚨 SECURITY ALERT - SecurityWatch Pro")
        print("="*60)
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Events: {len(events)} security events detected")
        
        # Show summary by severity
        severity_count = {}
        for event in events:
            severity_count[event.severity] = severity_count.get(event.severity, 0) + 1
        
        for severity, count in severity_count.items():
            print(f"{severity.upper()}: {count}")
        
        # Show top events
        print("\nTop Events:")
        for i, event in enumerate(events[:5], 1):
            print(f"{i}. {event.event_type.replace('_', ' ').title()} from {event.source_ip or 'Unknown'}")
        
        if len(events) > 5:
            print(f"... and {len(events) - 5} more events")
        
        print("="*60)
    
    def _log_alert(self, events: List[SecurityEvent]):
        """Log alert to file"""
        self.logger.warning(f"SECURITY ALERT: {len(events)} events detected")
        
        severity_count = {}
        for event in events:
            severity_count[event.severity] = severity_count.get(event.severity, 0) + 1
        
        for severity, count in severity_count.items():
            self.logger.warning(f"  {severity.upper()}: {count} events")
    
    def send_test_alert(self) -> bool:
        """Send a test alert to verify configuration"""
        try:
            if self.config.email.enabled:
                # Create test email
                msg = MIMEMultipart()
                msg['From'] = self.config.email.from_email
                msg['To'] = ', '.join(self.config.email.to_emails)
                msg['Subject'] = "SecurityWatch Pro - Test Alert"
                
                body = """
                <html>
                <body>
                    <h2>🧪 SecurityWatch Pro Test Alert</h2>
                    <p>This is a test alert to verify your email configuration.</p>
                    <p>If you received this email, your alert system is working correctly!</p>
                    <p><strong>Time:</strong> {}</p>
                </body>
                </html>
                """.format(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                
                msg.attach(MIMEText(body, 'html'))
                
                # Send email
                with smtplib.SMTP(self.config.email.smtp_server, self.config.email.smtp_port) as server:
                    if self.config.email.use_tls:
                        server.starttls()
                    
                    if self.config.email.username and self.config.email.password:
                        server.login(self.config.email.username, self.config.email.password)
                    
                    server.send_message(msg)
                
                self.logger.info("Test alert sent successfully")
                return True
            else:
                self.logger.warning("Email not configured, cannot send test alert")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to send test alert: {e}")
            return False
