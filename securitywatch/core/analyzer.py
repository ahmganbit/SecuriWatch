"""
SecurityWatch Pro - Threat Analysis Engine
"""

from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Dict, List, Any

from ..models.events import SecurityEvent
from .database import SecurityDatabase


class ThreatAnalyzer:
    """Advanced threat analysis and correlation"""
    
    def __init__(self, database: SecurityDatabase):
        self.database = database
        self.event_cache = defaultdict(list)
    
    def analyze_events(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Perform comprehensive threat analysis"""
        analysis = {
            'total_events': len(events),
            'severity_breakdown': Counter(),
            'top_source_ips': Counter(),
            'top_usernames': Counter(),
            'attack_patterns': [],
            'brute_force_attempts': [],
            'geographic_analysis': {},
            'recommendations': [],
            'timeline_analysis': {},
            'threat_score': 0
        }
        
        # Basic statistics
        for event in events:
            analysis['severity_breakdown'][event.severity] += 1
            if event.source_ip:
                analysis['top_source_ips'][event.source_ip] += 1
            if event.username:
                analysis['top_usernames'][event.username] += 1
        
        # Detect brute force attacks
        analysis['brute_force_attempts'] = self._detect_brute_force(events)
        
        # Analyze timeline patterns
        analysis['timeline_analysis'] = self._analyze_timeline(events)
        
        # Calculate threat score
        analysis['threat_score'] = self._calculate_threat_score(analysis)
        
        # Generate recommendations
        analysis['recommendations'] = self._generate_recommendations(analysis)
        
        return analysis
    
    def _detect_brute_force(self, events: List[SecurityEvent]) -> List[Dict]:
        """Detect brute force attack patterns"""
        brute_force_attacks = []
        
        # Group events by IP and time window
        ip_events = defaultdict(list)
        for event in events:
            if event.source_ip and event.event_type in [
                'ssh_failed_login', 'windows_failed_login', 'failed_root_login',
                'multiple_authentication_failures'
            ]:
                ip_events[event.source_ip].append(event)
        
        # Analyze each IP for brute force patterns
        for ip, ip_event_list in ip_events.items():
            if len(ip_event_list) >= 5:  # Threshold for brute force
                # Check if events are within time window
                timestamps = [e.timestamp for e in ip_event_list]
                timestamps.sort()
                
                time_span = (timestamps[-1] - timestamps[0]).total_seconds()
                if time_span <= 600:  # 10 minutes
                    severity = 'critical' if len(ip_event_list) > 20 else 'high'
                    if len(ip_event_list) > 50:
                        severity = 'critical'
                    
                    brute_force_attacks.append({
                        'source_ip': ip,
                        'attempt_count': len(ip_event_list),
                        'time_span_seconds': time_span,
                        'usernames_targeted': list(set(e.username for e in ip_event_list if e.username)),
                        'first_attempt': timestamps[0],
                        'last_attempt': timestamps[-1],
                        'severity': severity,
                        'attack_rate': len(ip_event_list) / (time_span / 60) if time_span > 0 else 0  # attempts per minute
                    })
        
        return sorted(brute_force_attacks, key=lambda x: x['attempt_count'], reverse=True)
    
    def _analyze_timeline(self, events: List[SecurityEvent]) -> Dict:
        """Analyze event timeline patterns"""
        if not events:
            return {}
        
        # Group events by hour
        hourly_events = defaultdict(int)
        daily_events = defaultdict(int)
        
        for event in events:
            hour = event.timestamp.hour
            day = event.timestamp.strftime('%Y-%m-%d')
            hourly_events[hour] += 1
            daily_events[day] += 1
        
        # Find peak hours and days
        peak_hour = max(hourly_events.items(), key=lambda x: x[1]) if hourly_events else (0, 0)
        peak_day = max(daily_events.items(), key=lambda x: x[1]) if daily_events else ('', 0)
        
        return {
            'hourly_distribution': dict(hourly_events),
            'daily_distribution': dict(daily_events),
            'peak_hour': {'hour': peak_hour[0], 'events': peak_hour[1]},
            'peak_day': {'date': peak_day[0], 'events': peak_day[1]},
            'total_days_with_events': len(daily_events)
        }
    
    def _calculate_threat_score(self, analysis: Dict) -> int:
        """Calculate overall threat score (0-100)"""
        score = 0
        
        # Base score from event count
        event_count = analysis['total_events']
        if event_count > 100:
            score += 30
        elif event_count > 50:
            score += 20
        elif event_count > 10:
            score += 10
        
        # Severity weighting
        severity_scores = {
            'critical': 25,
            'high': 15,
            'medium': 5,
            'low': 1
        }
        
        for severity, count in analysis['severity_breakdown'].items():
            score += min(severity_scores.get(severity, 0) * count, 40)
        
        # Brute force attacks
        brute_force_count = len(analysis['brute_force_attempts'])
        if brute_force_count > 0:
            score += min(brute_force_count * 10, 30)
        
        return min(score, 100)
    
    def _generate_recommendations(self, analysis: Dict) -> List[str]:
        """Generate actionable security recommendations"""
        recommendations = []
        
        # High number of failed logins
        if analysis['total_events'] > 100:
            recommendations.append("⚠️ High volume of security events detected. Consider implementing rate limiting or account lockout policies")
        
        # Brute force attacks detected
        if analysis['brute_force_attempts']:
            recommendations.append("🚨 Brute force attacks detected. Implement fail2ban or similar IP blocking mechanisms")
            recommendations.append("🔒 Consider changing default SSH port and disabling root login")
            
            # Specific IP recommendations
            for attack in analysis['brute_force_attempts'][:3]:  # Top 3 attackers
                recommendations.append(f"🛡️ Block IP {attack['source_ip']} immediately ({attack['attempt_count']} failed attempts)")
        
        # High severity events
        critical_count = analysis['severity_breakdown'].get('critical', 0)
        if critical_count > 0:
            recommendations.append(f"🔥 {critical_count} critical security events require immediate investigation")
        
        # Top attacking IPs
        if analysis['top_source_ips']:
            top_ip = analysis['top_source_ips'].most_common(1)[0]
            if top_ip[1] > 10:
                recommendations.append(f"🎯 IP {top_ip[0]} is a repeat offender ({top_ip[1]} events) - consider permanent blocking")
        
        # Username analysis
        if analysis['top_usernames']:
            top_username = analysis['top_usernames'].most_common(1)[0]
            if top_username[1] > 20:
                recommendations.append(f"👤 Username '{top_username[0]}' is heavily targeted - ensure strong password policy")
        
        # Threat score based recommendations
        threat_score = analysis.get('threat_score', 0)
        if threat_score > 70:
            recommendations.append("🚨 CRITICAL: Very high threat level detected. Immediate security review required")
        elif threat_score > 40:
            recommendations.append("⚠️ HIGH: Elevated threat level. Enhanced monitoring recommended")
        elif threat_score > 20:
            recommendations.append("📊 MEDIUM: Moderate threat level. Regular monitoring sufficient")
        
        # Timeline-based recommendations
        timeline = analysis.get('timeline_analysis', {})
        if timeline.get('peak_hour', {}).get('events', 0) > 50:
            peak_hour = timeline['peak_hour']['hour']
            recommendations.append(f"⏰ Peak attack time: {peak_hour}:00. Consider enhanced monitoring during this hour")
        
        return recommendations
    
    def get_ip_analysis(self, ip_address: str, hours: int = 24) -> Dict:
        """Get detailed analysis for a specific IP address"""
        events = self.database.get_recent_events(hours)
        ip_events = [e for e in events if e.source_ip == ip_address]
        
        if not ip_events:
            return {'ip': ip_address, 'events': [], 'analysis': 'No recent activity'}
        
        analysis = {
            'ip': ip_address,
            'total_events': len(ip_events),
            'event_types': Counter(e.event_type for e in ip_events),
            'severity_breakdown': Counter(e.severity for e in ip_events),
            'usernames_targeted': list(set(e.username for e in ip_events if e.username)),
            'first_seen': min(e.timestamp for e in ip_events),
            'last_seen': max(e.timestamp for e in ip_events),
            'is_brute_force': len(ip_events) >= 5,
            'threat_level': 'high' if len(ip_events) > 20 else 'medium' if len(ip_events) > 5 else 'low'
        }
        
        return analysis
