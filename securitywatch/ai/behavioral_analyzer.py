"""
SecurityWatch Pro - Behavioral Analysis Engine
Advanced behavioral analysis for detecting sophisticated attacks and insider threats
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional
from collections import defaultdict, deque
import logging

from ..models.events import SecurityEvent
from ..core.database import SecurityDatabase


class BehavioralAnalyzer:
    """Advanced behavioral analysis for security events"""
    
    def __init__(self, database: SecurityDatabase):
        self.database = database
        self.logger = logging.getLogger('SecurityWatch.AI.BehavioralAnalyzer')
        
        # Behavioral baselines
        self.user_baselines = {}
        self.ip_baselines = {}
        self.system_baseline = {}
        
        # Learning parameters
        self.learning_window_days = 30
        self.min_events_for_baseline = 50
        
        # Behavioral patterns
        self.behavioral_patterns = {
            'time_patterns': {},
            'access_patterns': {},
            'frequency_patterns': {},
            'sequence_patterns': {}
        }
        
        # Initialize baselines
        self._initialize_baselines()
    
    def _initialize_baselines(self):
        """Initialize behavioral baselines from historical data"""
        self.logger.info("Initializing behavioral baselines...")
        
        # Get historical data for baseline learning
        events = self.database.get_recent_events(self.learning_window_days * 24)
        
        if len(events) < self.min_events_for_baseline:
            self.logger.warning(f"Insufficient data for baseline learning. Need at least {self.min_events_for_baseline} events.")
            return
        
        # Build user baselines
        self._build_user_baselines(events)
        
        # Build IP baselines
        self._build_ip_baselines(events)
        
        # Build system baseline
        self._build_system_baseline(events)
        
        self.logger.info("Behavioral baselines initialized successfully")
    
    def _build_user_baselines(self, events: List[SecurityEvent]):
        """Build behavioral baselines for users"""
        user_events = defaultdict(list)
        
        for event in events:
            if event.username:
                user_events[event.username].append(event)
        
        for username, user_event_list in user_events.items():
            if len(user_event_list) >= 10:  # Minimum events for user baseline
                baseline = self._calculate_user_baseline(user_event_list)
                self.user_baselines[username] = baseline
    
    def _calculate_user_baseline(self, events: List[SecurityEvent]) -> Dict:
        """Calculate behavioral baseline for a specific user"""
        # Time patterns
        hours = [event.timestamp.hour for event in events]
        days = [event.timestamp.weekday() for event in events]
        
        # Access patterns
        event_types = [event.event_type for event in events]
        source_ips = [event.source_ip for event in events if event.source_ip]
        
        # Frequency patterns
        daily_counts = defaultdict(int)
        for event in events:
            day_key = event.timestamp.date()
            daily_counts[day_key] += 1
        
        return {
            'time_patterns': {
                'typical_hours': self._get_typical_hours(hours),
                'typical_days': self._get_typical_days(days),
                'hour_distribution': np.histogram(hours, bins=24)[0].tolist(),
                'day_distribution': np.histogram(days, bins=7)[0].tolist()
            },
            'access_patterns': {
                'common_event_types': self._get_common_items(event_types, top_n=5),
                'common_source_ips': self._get_common_items(source_ips, top_n=3),
                'event_type_diversity': len(set(event_types)),
                'ip_diversity': len(set(source_ips))
            },
            'frequency_patterns': {
                'avg_daily_events': np.mean(list(daily_counts.values())),
                'std_daily_events': np.std(list(daily_counts.values())),
                'max_daily_events': max(daily_counts.values()) if daily_counts else 0,
                'total_events': len(events)
            },
            'baseline_period': {
                'start_date': min(event.timestamp for event in events).isoformat(),
                'end_date': max(event.timestamp for event in events).isoformat(),
                'event_count': len(events)
            }
        }
    
    def _build_ip_baselines(self, events: List[SecurityEvent]):
        """Build behavioral baselines for IP addresses"""
        ip_events = defaultdict(list)
        
        for event in events:
            if event.source_ip:
                ip_events[event.source_ip].append(event)
        
        for ip, ip_event_list in ip_events.items():
            if len(ip_event_list) >= 5:  # Minimum events for IP baseline
                baseline = self._calculate_ip_baseline(ip_event_list)
                self.ip_baselines[ip] = baseline
    
    def _calculate_ip_baseline(self, events: List[SecurityEvent]) -> Dict:
        """Calculate behavioral baseline for a specific IP"""
        # Time patterns
        hours = [event.timestamp.hour for event in events]
        
        # User patterns
        usernames = [event.username for event in events if event.username]
        
        # Event patterns
        event_types = [event.event_type for event in events]
        severities = [event.severity for event in events]
        
        # Timing patterns
        timestamps = sorted([event.timestamp for event in events])
        time_intervals = []
        for i in range(1, len(timestamps)):
            interval = (timestamps[i] - timestamps[i-1]).total_seconds()
            time_intervals.append(interval)
        
        return {
            'time_patterns': {
                'typical_hours': self._get_typical_hours(hours),
                'hour_distribution': np.histogram(hours, bins=24)[0].tolist()
            },
            'user_patterns': {
                'unique_users': len(set(usernames)),
                'common_users': self._get_common_items(usernames, top_n=3),
                'user_diversity_score': len(set(usernames)) / len(events) if events else 0
            },
            'event_patterns': {
                'common_event_types': self._get_common_items(event_types, top_n=3),
                'severity_distribution': {sev: severities.count(sev) for sev in set(severities)},
                'event_diversity': len(set(event_types))
            },
            'timing_patterns': {
                'avg_interval_seconds': np.mean(time_intervals) if time_intervals else 0,
                'std_interval_seconds': np.std(time_intervals) if time_intervals else 0,
                'min_interval_seconds': min(time_intervals) if time_intervals else 0,
                'is_rhythmic': self._is_rhythmic_pattern(time_intervals)
            },
            'baseline_period': {
                'start_date': min(event.timestamp for event in events).isoformat(),
                'end_date': max(event.timestamp for event in events).isoformat(),
                'event_count': len(events)
            }
        }
    
    def _build_system_baseline(self, events: List[SecurityEvent]):
        """Build system-wide behavioral baseline"""
        # Overall system patterns
        hours = [event.timestamp.hour for event in events]
        days = [event.timestamp.weekday() for event in events]
        event_types = [event.event_type for event in events]
        severities = [event.severity for event in events]
        
        # Daily event counts
        daily_counts = defaultdict(int)
        for event in events:
            day_key = event.timestamp.date()
            daily_counts[day_key] += 1
        
        self.system_baseline = {
            'time_patterns': {
                'peak_hours': self._get_peak_hours(hours),
                'quiet_hours': self._get_quiet_hours(hours),
                'business_hours_ratio': self._calculate_business_hours_ratio(hours),
                'weekend_ratio': self._calculate_weekend_ratio(days)
            },
            'event_patterns': {
                'common_event_types': self._get_common_items(event_types, top_n=10),
                'severity_baseline': {sev: severities.count(sev) / len(severities) for sev in set(severities)},
                'total_event_types': len(set(event_types))
            },
            'volume_patterns': {
                'avg_daily_events': np.mean(list(daily_counts.values())),
                'std_daily_events': np.std(list(daily_counts.values())),
                'peak_daily_events': max(daily_counts.values()) if daily_counts else 0,
                'baseline_period_days': len(daily_counts)
            }
        }
    
    def analyze_behavioral_anomalies(self, events: List[SecurityEvent]) -> List[Dict]:
        """Analyze events for behavioral anomalies"""
        anomalies = []
        
        # Group events by user and IP for analysis
        user_events = defaultdict(list)
        ip_events = defaultdict(list)
        
        for event in events:
            if event.username:
                user_events[event.username].append(event)
            if event.source_ip:
                ip_events[event.source_ip].append(event)
        
        # Analyze user behavioral anomalies
        for username, user_event_list in user_events.items():
            user_anomalies = self._analyze_user_anomalies(username, user_event_list)
            anomalies.extend(user_anomalies)
        
        # Analyze IP behavioral anomalies
        for ip, ip_event_list in ip_events.items():
            ip_anomalies = self._analyze_ip_anomalies(ip, ip_event_list)
            anomalies.extend(ip_anomalies)
        
        # Analyze system-wide anomalies
        system_anomalies = self._analyze_system_anomalies(events)
        anomalies.extend(system_anomalies)
        
        return anomalies
    
    def _analyze_user_anomalies(self, username: str, events: List[SecurityEvent]) -> List[Dict]:
        """Analyze behavioral anomalies for a specific user"""
        anomalies = []
        
        if username not in self.user_baselines:
            # New user - create baseline if enough events
            if len(events) >= 10:
                self.user_baselines[username] = self._calculate_user_baseline(events)
            return anomalies
        
        baseline = self.user_baselines[username]
        
        # Time-based anomalies
        current_hours = [event.timestamp.hour for event in events]
        typical_hours = set(baseline['time_patterns']['typical_hours'])
        
        unusual_hours = [h for h in current_hours if h not in typical_hours]
        if len(unusual_hours) > len(current_hours) * 0.5:  # More than 50% unusual hours
            anomalies.append({
                'type': 'unusual_time_pattern',
                'entity': username,
                'entity_type': 'user',
                'severity': 'medium',
                'description': f"User {username} active during unusual hours: {set(unusual_hours)}",
                'confidence': 0.7,
                'details': {
                    'unusual_hours': list(set(unusual_hours)),
                    'typical_hours': baseline['time_patterns']['typical_hours']
                }
            })
        
        # Frequency anomalies
        current_event_count = len(events)
        baseline_avg = baseline['frequency_patterns']['avg_daily_events']
        baseline_std = baseline['frequency_patterns']['std_daily_events']
        
        if current_event_count > baseline_avg + 3 * baseline_std:
            anomalies.append({
                'type': 'unusual_activity_volume',
                'entity': username,
                'entity_type': 'user',
                'severity': 'high',
                'description': f"User {username} has unusually high activity: {current_event_count} events",
                'confidence': 0.8,
                'details': {
                    'current_count': current_event_count,
                    'baseline_avg': baseline_avg,
                    'deviation_factor': (current_event_count - baseline_avg) / baseline_std if baseline_std > 0 else 0
                }
            })
        
        # Access pattern anomalies
        current_event_types = set(event.event_type for event in events)
        baseline_event_types = set(baseline['access_patterns']['common_event_types'])
        
        new_event_types = current_event_types - baseline_event_types
        if len(new_event_types) > 2:  # More than 2 new event types
            anomalies.append({
                'type': 'unusual_access_pattern',
                'entity': username,
                'entity_type': 'user',
                'severity': 'medium',
                'description': f"User {username} exhibiting new access patterns: {new_event_types}",
                'confidence': 0.6,
                'details': {
                    'new_event_types': list(new_event_types),
                    'baseline_event_types': baseline['access_patterns']['common_event_types']
                }
            })
        
        return anomalies
    
    def _analyze_ip_anomalies(self, ip: str, events: List[SecurityEvent]) -> List[Dict]:
        """Analyze behavioral anomalies for a specific IP"""
        anomalies = []
        
        if ip not in self.ip_baselines:
            # New IP - check for suspicious patterns
            if len(events) >= 5:
                self.ip_baselines[ip] = self._calculate_ip_baseline(events)
                
                # Check for immediate red flags in new IPs
                if self._is_suspicious_new_ip(events):
                    anomalies.append({
                        'type': 'suspicious_new_ip',
                        'entity': ip,
                        'entity_type': 'ip',
                        'severity': 'high',
                        'description': f"New IP {ip} showing suspicious behavior patterns",
                        'confidence': 0.8,
                        'details': self._get_suspicious_ip_details(events)
                    })
            return anomalies
        
        baseline = self.ip_baselines[ip]
        
        # Timing pattern anomalies
        timestamps = sorted([event.timestamp for event in events])
        if len(timestamps) > 1:
            current_intervals = []
            for i in range(1, len(timestamps)):
                interval = (timestamps[i] - timestamps[i-1]).total_seconds()
                current_intervals.append(interval)
            
            baseline_avg_interval = baseline['timing_patterns']['avg_interval_seconds']
            current_avg_interval = np.mean(current_intervals)
            
            # Check for automation (very consistent timing)
            if (baseline['timing_patterns']['is_rhythmic'] and 
                abs(current_avg_interval - baseline_avg_interval) < 5):  # Within 5 seconds
                anomalies.append({
                    'type': 'automated_behavior',
                    'entity': ip,
                    'entity_type': 'ip',
                    'severity': 'high',
                    'description': f"IP {ip} showing automated/scripted behavior",
                    'confidence': 0.9,
                    'details': {
                        'avg_interval': current_avg_interval,
                        'baseline_interval': baseline_avg_interval,
                        'consistency_score': 1 - (np.std(current_intervals) / np.mean(current_intervals)) if current_intervals else 0
                    }
                })
        
        # User targeting anomalies
        current_users = set(event.username for event in events if event.username)
        baseline_user_diversity = baseline['user_patterns']['user_diversity_score']
        current_user_diversity = len(current_users) / len(events) if events else 0
        
        if current_user_diversity > baseline_user_diversity * 2:
            anomalies.append({
                'type': 'user_enumeration',
                'entity': ip,
                'entity_type': 'ip',
                'severity': 'medium',
                'description': f"IP {ip} targeting unusually diverse set of users",
                'confidence': 0.7,
                'details': {
                    'current_user_count': len(current_users),
                    'baseline_diversity': baseline_user_diversity,
                    'current_diversity': current_user_diversity
                }
            })
        
        return anomalies
    
    def _analyze_system_anomalies(self, events: List[SecurityEvent]) -> List[Dict]:
        """Analyze system-wide behavioral anomalies"""
        anomalies = []
        
        if not self.system_baseline:
            return anomalies
        
        # Volume anomalies
        current_volume = len(events)
        baseline_avg = self.system_baseline['volume_patterns']['avg_daily_events']
        baseline_std = self.system_baseline['volume_patterns']['std_daily_events']
        
        if current_volume > baseline_avg + 2 * baseline_std:
            anomalies.append({
                'type': 'system_volume_spike',
                'entity': 'system',
                'entity_type': 'system',
                'severity': 'medium',
                'description': f"System experiencing unusual volume spike: {current_volume} events",
                'confidence': 0.8,
                'details': {
                    'current_volume': current_volume,
                    'baseline_avg': baseline_avg,
                    'deviation_factor': (current_volume - baseline_avg) / baseline_std if baseline_std > 0 else 0
                }
            })
        
        # Severity distribution anomalies
        current_severities = [event.severity for event in events]
        current_critical_ratio = current_severities.count('critical') / len(current_severities) if current_severities else 0
        baseline_critical_ratio = self.system_baseline['event_patterns']['severity_baseline'].get('critical', 0)
        
        if current_critical_ratio > baseline_critical_ratio * 3:
            anomalies.append({
                'type': 'severity_spike',
                'entity': 'system',
                'entity_type': 'system',
                'severity': 'high',
                'description': f"Unusual spike in critical severity events: {current_critical_ratio:.1%}",
                'confidence': 0.9,
                'details': {
                    'current_critical_ratio': current_critical_ratio,
                    'baseline_critical_ratio': baseline_critical_ratio,
                    'critical_events': current_severities.count('critical')
                }
            })
        
        return anomalies
    
    def _is_suspicious_new_ip(self, events: List[SecurityEvent]) -> bool:
        """Check if a new IP shows suspicious patterns"""
        if len(events) < 3:
            return False
        
        # Check for rapid-fire events
        timestamps = sorted([event.timestamp for event in events])
        time_span = (timestamps[-1] - timestamps[0]).total_seconds()
        
        if time_span < 60 and len(events) > 10:  # More than 10 events in 1 minute
            return True
        
        # Check for diverse user targeting
        usernames = set(event.username for event in events if event.username)
        if len(usernames) > 5:  # Targeting more than 5 users
            return True
        
        # Check for high severity events
        critical_count = sum(1 for event in events if event.severity == 'critical')
        if critical_count > len(events) * 0.5:  # More than 50% critical
            return True
        
        return False
    
    def _get_suspicious_ip_details(self, events: List[SecurityEvent]) -> Dict:
        """Get details about suspicious IP behavior"""
        timestamps = sorted([event.timestamp for event in events])
        usernames = [event.username for event in events if event.username]
        severities = [event.severity for event in events]
        
        return {
            'event_count': len(events),
            'time_span_seconds': (timestamps[-1] - timestamps[0]).total_seconds() if len(timestamps) > 1 else 0,
            'unique_users_targeted': len(set(usernames)),
            'critical_events': severities.count('critical'),
            'event_rate_per_minute': len(events) / max((timestamps[-1] - timestamps[0]).total_seconds() / 60, 1) if len(timestamps) > 1 else 0
        }
    
    def _get_typical_hours(self, hours: List[int]) -> List[int]:
        """Get typical hours of activity (hours with >10% of activity)"""
        if not hours:
            return []
        
        hour_counts = np.histogram(hours, bins=24)[0]
        total_events = sum(hour_counts)
        threshold = total_events * 0.1  # 10% threshold
        
        return [i for i, count in enumerate(hour_counts) if count >= threshold]
    
    def _get_typical_days(self, days: List[int]) -> List[int]:
        """Get typical days of activity"""
        if not days:
            return []
        
        day_counts = np.histogram(days, bins=7)[0]
        total_events = sum(day_counts)
        threshold = total_events * 0.1
        
        return [i for i, count in enumerate(day_counts) if count >= threshold]
    
    def _get_common_items(self, items: List, top_n: int = 5) -> List:
        """Get most common items from a list"""
        if not items:
            return []
        
        from collections import Counter
        counter = Counter(items)
        return [item for item, count in counter.most_common(top_n)]
    
    def _get_peak_hours(self, hours: List[int]) -> List[int]:
        """Get peak activity hours"""
        if not hours:
            return []
        
        hour_counts = np.histogram(hours, bins=24)[0]
        max_count = max(hour_counts)
        threshold = max_count * 0.8  # 80% of peak
        
        return [i for i, count in enumerate(hour_counts) if count >= threshold]
    
    def _get_quiet_hours(self, hours: List[int]) -> List[int]:
        """Get quiet activity hours"""
        if not hours:
            return []
        
        hour_counts = np.histogram(hours, bins=24)[0]
        avg_count = np.mean(hour_counts)
        threshold = avg_count * 0.3  # 30% of average
        
        return [i for i, count in enumerate(hour_counts) if count <= threshold]
    
    def _calculate_business_hours_ratio(self, hours: List[int]) -> float:
        """Calculate ratio of events during business hours (9-17)"""
        if not hours:
            return 0.0
        
        business_hours_events = sum(1 for hour in hours if 9 <= hour <= 17)
        return business_hours_events / len(hours)
    
    def _calculate_weekend_ratio(self, days: List[int]) -> float:
        """Calculate ratio of events during weekends"""
        if not days:
            return 0.0
        
        weekend_events = sum(1 for day in days if day >= 5)  # Saturday=5, Sunday=6
        return weekend_events / len(days)
    
    def _is_rhythmic_pattern(self, intervals: List[float]) -> bool:
        """Check if timing intervals show rhythmic pattern"""
        if len(intervals) < 3:
            return False
        
        # Calculate coefficient of variation
        mean_interval = np.mean(intervals)
        std_interval = np.std(intervals)
        
        if mean_interval == 0:
            return False
        
        cv = std_interval / mean_interval
        return cv < 0.2  # Low variation indicates rhythmic pattern
    
    def get_baseline_summary(self) -> Dict:
        """Get summary of current behavioral baselines"""
        return {
            'user_baselines_count': len(self.user_baselines),
            'ip_baselines_count': len(self.ip_baselines),
            'system_baseline_exists': bool(self.system_baseline),
            'learning_window_days': self.learning_window_days,
            'min_events_for_baseline': self.min_events_for_baseline,
            'last_updated': datetime.now().isoformat()
        }
