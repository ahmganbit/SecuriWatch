"""
SecurityWatch Pro - Report Generation
"""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict

from ..models.events import SecurityEvent
from .database import SecurityDatabase
from .analyzer import ThreatAnalyzer


class ReportGenerator:
    """Generate comprehensive security reports"""
    
    def __init__(self, database: SecurityDatabase):
        self.database = database
        self.analyzer = ThreatAnalyzer(database)
    
    def generate_html_report(self, hours: int = 24) -> str:
        """Generate comprehensive HTML security report"""
        # Get recent events
        events = self.database.get_recent_events(hours)
        
        # Analyze threats
        analysis = self.analyzer.analyze_events(events)
        
        # Get database statistics
        stats = self.database.get_statistics()
        
        # Generate HTML report
        html_report = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SecurityWatch Pro Report</title>
            <meta charset="UTF-8">
            <style>
                body {{ 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                    margin: 0; 
                    padding: 20px; 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                }}
                .container {{ 
                    max-width: 1200px; 
                    margin: 0 auto; 
                    background: white; 
                    border-radius: 10px; 
                    box-shadow: 0 10px 30px rgba(0,0,0,0.3);
                    overflow: hidden;
                }}
                .header {{ 
                    background: linear-gradient(135deg, #c0392b 0%, #e74c3c 100%); 
                    color: white; 
                    padding: 30px; 
                    text-align: center;
                }}
                .header h1 {{ margin: 0; font-size: 2.5em; }}
                .header p {{ margin: 10px 0 0 0; opacity: 0.9; }}
                .content {{ padding: 30px; }}
                .summary {{ 
                    display: grid; 
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
                    gap: 20px; 
                    margin-bottom: 30px; 
                }}
                .summary-card {{ 
                    background: #f8f9fa; 
                    padding: 20px; 
                    border-radius: 8px; 
                    border-left: 4px solid #3498db;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }}
                .summary-card h3 {{ margin: 0 0 10px 0; color: #2c3e50; }}
                .summary-card .number {{ font-size: 2em; font-weight: bold; color: #3498db; }}
                .alert {{ background: #e74c3c; color: white; padding: 15px; margin: 10px 0; border-radius: 5px; }}
                .warning {{ background: #f39c12; color: white; padding: 15px; margin: 10px 0; border-radius: 5px; }}
                .info {{ background: #3498db; color: white; padding: 15px; margin: 10px 0; border-radius: 5px; }}
                .success {{ background: #2ecc71; color: white; padding: 15px; margin: 10px 0; border-radius: 5px; }}
                .table {{ 
                    width: 100%; 
                    border-collapse: collapse; 
                    margin: 20px 0; 
                    background: white;
                    border-radius: 8px;
                    overflow: hidden;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }}
                .table th, .table td {{ 
                    border: none; 
                    padding: 15px; 
                    text-align: left; 
                    border-bottom: 1px solid #ecf0f1;
                }}
                .table th {{ 
                    background: #34495e; 
                    color: white; 
                    font-weight: 600;
                }}
                .table tr:hover {{ background: #f8f9fa; }}
                .recommendations {{ 
                    background: linear-gradient(135deg, #2ecc71 0%, #27ae60 100%); 
                    color: white; 
                    padding: 25px; 
                    border-radius: 8px; 
                    margin: 20px 0; 
                }}
                .chart {{ 
                    background: white; 
                    padding: 25px; 
                    border-radius: 8px; 
                    margin: 20px 0; 
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }}
                .severity-critical {{ color: #e74c3c; font-weight: bold; }}
                .severity-high {{ color: #f39c12; font-weight: bold; }}
                .severity-medium {{ color: #3498db; font-weight: bold; }}
                .severity-low {{ color: #95a5a6; }}
                .footer {{ 
                    background: #2c3e50; 
                    color: white; 
                    padding: 20px; 
                    text-align: center; 
                }}
                .threat-score {{
                    font-size: 3em;
                    font-weight: bold;
                    text-align: center;
                    padding: 20px;
                    border-radius: 50%;
                    width: 120px;
                    height: 120px;
                    margin: 0 auto;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }}
                .threat-low {{ background: #2ecc71; color: white; }}
                .threat-medium {{ background: #f39c12; color: white; }}
                .threat-high {{ background: #e74c3c; color: white; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ SecurityWatch Pro Report</h1>
                    <p>Security Analysis Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    <p>Analysis Period: Last {hours} hours</p>
                </div>
                
                <div class="content">
                    <div class="summary">
                        <div class="summary-card">
                            <h3>📊 Total Events</h3>
                            <div class="number">{analysis['total_events']}</div>
                        </div>
                        <div class="summary-card">
                            <h3>🔥 Critical Events</h3>
                            <div class="number">{analysis['severity_breakdown'].get('critical', 0)}</div>
                        </div>
                        <div class="summary-card">
                            <h3>⚠️ High Severity</h3>
                            <div class="number">{analysis['severity_breakdown'].get('high', 0)}</div>
                        </div>
                        <div class="summary-card">
                            <h3>🎯 Brute Force Attacks</h3>
                            <div class="number">{len(analysis['brute_force_attempts'])}</div>
                        </div>
                    </div>
                    
                    <div class="chart">
                        <h2>🎯 Threat Score</h2>
                        <div class="threat-score {self._get_threat_class(analysis['threat_score'])}">
                            {analysis['threat_score']}
                        </div>
                        <p style="text-align: center; margin-top: 20px;">
                            {self._get_threat_description(analysis['threat_score'])}
                        </p>
                    </div>
        """
        
        # Brute force attacks section
        if analysis['brute_force_attempts']:
            html_report += """
            <div class="alert">
                <h2>🚨 Brute Force Attacks Detected</h2>
                <p>The following IP addresses have been identified as conducting brute force attacks:</p>
            </div>
            <table class="table">
                <tr>
                    <th>Source IP</th>
                    <th>Attempts</th>
                    <th>Time Span</th>
                    <th>Usernames Targeted</th>
                    <th>Severity</th>
                </tr>
            """
            
            for attack in analysis['brute_force_attempts'][:10]:
                usernames = ', '.join(attack['usernames_targeted'][:3])
                if len(attack['usernames_targeted']) > 3:
                    usernames += f" (+{len(attack['usernames_targeted']) - 3} more)"
                
                html_report += f"""
                <tr>
                    <td>{attack['source_ip']}</td>
                    <td>{attack['attempt_count']}</td>
                    <td>{attack['time_span_seconds']:.0f}s</td>
                    <td>{usernames}</td>
                    <td class="severity-{attack['severity']}">{attack['severity'].upper()}</td>
                </tr>
                """
            
            html_report += "</table>"
        
        # Top attacking IPs
        if analysis['top_source_ips']:
            html_report += """
            <div class="chart">
                <h2>🌐 Top Attacking IP Addresses</h2>
                <table class="table">
                    <tr>
                        <th>IP Address</th>
                        <th>Event Count</th>
                        <th>Percentage</th>
                    </tr>
            """
            
            total_events = sum(analysis['top_source_ips'].values())
            for ip, count in analysis['top_source_ips'].most_common(10):
                percentage = (count / total_events * 100) if total_events > 0 else 0
                html_report += f"""
                <tr>
                    <td>{ip}</td>
                    <td>{count}</td>
                    <td>{percentage:.1f}%</td>
                </tr>
                """
            
            html_report += "</table></div>"
        
        # Recommendations
        if analysis['recommendations']:
            html_report += """
            <div class="recommendations">
                <h2>💡 Security Recommendations</h2>
                <ul>
            """
            
            for recommendation in analysis['recommendations']:
                html_report += f"<li>{recommendation}</li>"
            
            html_report += "</ul></div>"
        
        # Timeline analysis
        timeline = analysis.get('timeline_analysis', {})
        if timeline:
            html_report += f"""
            <div class="chart">
                <h2>📈 Timeline Analysis</h2>
                <p><strong>Peak Activity Hour:</strong> {timeline.get('peak_hour', {}).get('hour', 'N/A')}:00 
                   ({timeline.get('peak_hour', {}).get('events', 0)} events)</p>
                <p><strong>Days with Events:</strong> {timeline.get('total_days_with_events', 0)}</p>
            </div>
            """
        
        html_report += """
                </div>
                <div class="footer">
                    <p>Report generated by SecurityWatch Pro v1.0.0</p>
                    <p>For support, contact: support@sysadmintoolspro.com</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html_report
    
    def _get_threat_class(self, score: int) -> str:
        """Get CSS class for threat score"""
        if score >= 70:
            return "threat-high"
        elif score >= 40:
            return "threat-medium"
        else:
            return "threat-low"
    
    def _get_threat_description(self, score: int) -> str:
        """Get description for threat score"""
        if score >= 70:
            return "🚨 CRITICAL THREAT LEVEL - Immediate action required"
        elif score >= 40:
            return "⚠️ HIGH THREAT LEVEL - Enhanced monitoring recommended"
        elif score >= 20:
            return "📊 MEDIUM THREAT LEVEL - Regular monitoring sufficient"
        else:
            return "✅ LOW THREAT LEVEL - Normal security posture"
    
    def generate_json_report(self, hours: int = 24) -> Dict:
        """Generate JSON report for API consumption"""
        events = self.database.get_recent_events(hours)
        analysis = self.analyzer.analyze_events(events)
        stats = self.database.get_statistics()
        
        return {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'analysis_period_hours': hours,
                'version': '1.0.0'
            },
            'summary': {
                'total_events': analysis['total_events'],
                'severity_breakdown': dict(analysis['severity_breakdown']),
                'threat_score': analysis['threat_score'],
                'brute_force_attacks': len(analysis['brute_force_attempts'])
            },
            'top_attackers': [
                {'ip': ip, 'count': count} 
                for ip, count in analysis['top_source_ips'].most_common(10)
            ],
            'brute_force_details': analysis['brute_force_attempts'],
            'recommendations': analysis['recommendations'],
            'timeline_analysis': analysis.get('timeline_analysis', {}),
            'database_stats': stats
        }
    
    def save_report(self, report_type: str = 'html', hours: int = 24, 
                   filename: str = None) -> str:
        """Save report to file"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"securitywatch_report_{timestamp}.{report_type}"
        
        if report_type == 'html':
            content = self.generate_html_report(hours)
        elif report_type == 'json':
            content = json.dumps(self.generate_json_report(hours), indent=2, default=str)
        else:
            raise ValueError(f"Unsupported report type: {report_type}")
        
        # Create reports directory
        reports_dir = Path('reports')
        reports_dir.mkdir(exist_ok=True)
        
        # Save file
        file_path = reports_dir / filename
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return str(file_path)
