"""
SecurityWatch Pro - Main Monitoring Engine
"""

import logging
import time
import threading
from pathlib import Path
from typing import List, Dict
from datetime import datetime

from ..models.events import SecurityEvent
from ..config.settings import SecurityWatchConfig
from .database import SecurityDatabase
from .patterns import LogPatternMatcher
from .analyzer import ThreatAnalyzer
from .alerts import AlertManager


class SecurityWatchMonitor:
    """Main monitoring engine for SecurityWatch Pro"""
    
    def __init__(self, config: SecurityWatchConfig = None):
        self.config = config or SecurityWatchConfig()
        self.database = SecurityDatabase()
        self.pattern_matcher = LogPatternMatcher()
        self.threat_analyzer = ThreatAnalyzer(self.database)
        self.alert_manager = AlertManager(self.config)
        self.logger = self._setup_logging()
        self.running = False
        self.log_positions = {}  # Track file positions
        self.monitor_thread = None
        
    def _setup_logging(self) -> logging.Logger:
        """Setup enterprise-grade logging"""
        logger = logging.getLogger('SecurityWatchPro')
        logger.setLevel(logging.INFO)
        
        # Clear existing handlers
        logger.handlers.clear()
        
        # Create logs directory
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        
        # File handler
        file_handler = logging.FileHandler(log_dir / 'securitywatch.log')
        console_handler = logging.StreamHandler()
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    
    def monitor_log_file(self, log_path: str) -> List[SecurityEvent]:
        """Monitor a single log file for new entries"""
        events = []
        
        try:
            if not Path(log_path).exists():
                return events
            
            # Get current file position
            current_pos = self.log_positions.get(log_path, 0)
            
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Check if file was rotated (size decreased)
                f.seek(0, 2)  # Go to end
                file_size = f.tell()
                
                if file_size < current_pos:
                    # File was rotated, start from beginning
                    current_pos = 0
                    self.logger.info(f"Log rotation detected for {log_path}")
                
                f.seek(current_pos)
                new_lines = f.readlines()
                self.log_positions[log_path] = f.tell()
            
            # Process new lines
            for line in new_lines:
                line = line.strip()
                if line:
                    matched_events = self.pattern_matcher.match_patterns(line, log_path)
                    events.extend(matched_events)
            
        except Exception as e:
            self.logger.error(f"Error monitoring {log_path}: {e}")
        
        return events
    
    def check_all_logs(self) -> List[SecurityEvent]:
        """Check all configured log files"""
        all_events = []
        
        for log_path in self.config.monitoring.log_paths:
            events = self.monitor_log_file(log_path)
            all_events.extend(events)
        
        # Store events in database and update IP reputation
        for event in all_events:
            self.database.add_event(event)
            if event.source_ip:
                self.database.update_ip_reputation(event.source_ip, event.severity)
        
        # Send alerts if needed
        if all_events:
            self.alert_manager.process_events(all_events)
        
        return all_events
    
    def start_monitoring(self):
        """Start continuous monitoring"""
        if self.running:
            self.logger.warning("Monitoring is already running")
            return
        
        self.running = True
        self.logger.info("Starting SecurityWatch Pro monitoring...")
        
        # Initialize log positions for existing files
        for log_path in self.config.monitoring.log_paths:
            if Path(log_path).exists():
                try:
                    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                        f.seek(0, 2)  # Go to end
                        self.log_positions[log_path] = f.tell()
                except Exception as e:
                    self.logger.error(f"Error initializing position for {log_path}: {e}")
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()
        
        self.logger.info(f"Monitoring started. Watching {len(self.config.monitoring.log_paths)} log files")
    
    def stop_monitoring(self):
        """Stop continuous monitoring"""
        if not self.running:
            return
        
        self.running = False
        self.logger.info("Stopping SecurityWatch Pro monitoring...")
        
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
        
        self.logger.info("Monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                # Check all logs
                events = self.check_all_logs()
                
                if events:
                    self.logger.info(f"Detected {len(events)} security events")
                
                # Cleanup old events periodically
                if datetime.now().minute == 0:  # Once per hour
                    deleted = self.database.cleanup_old_events(self.config.monitoring.database_retention_days)
                    if deleted > 0:
                        self.logger.info(f"Cleaned up {deleted} old events")
                
                # Sleep for configured interval
                time.sleep(self.config.monitoring.check_interval)
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(10)  # Wait before retrying
    
    def get_status(self) -> Dict:
        """Get current monitoring status"""
        stats = self.database.get_statistics()
        
        return {
            'running': self.running,
            'log_files_monitored': len(self.config.monitoring.log_paths),
            'total_events': stats.get('total_events', 0),
            'events_by_severity': stats.get('by_severity', {}),
            'top_attacking_ips': stats.get('top_ips', [])[:5],
            'config_summary': self.config.get_config_summary()
        }
    
    def run_manual_scan(self) -> Dict:
        """Run a manual scan of all log files"""
        self.logger.info("Starting manual security scan...")
        
        # Reset positions to scan entire files
        old_positions = self.log_positions.copy()
        self.log_positions = {}
        
        try:
            events = self.check_all_logs()
            
            # Analyze events
            analysis = self.threat_analyzer.analyze_events(events)
            
            self.logger.info(f"Manual scan completed. Found {len(events)} events")
            
            return {
                'events_found': len(events),
                'analysis': analysis,
                'scan_time': datetime.now().isoformat()
            }
            
        finally:
            # Restore positions
            self.log_positions = old_positions
    
    def add_log_file(self, log_path: str) -> bool:
        """Add a new log file to monitor"""
        if not Path(log_path).exists():
            self.logger.error(f"Log file does not exist: {log_path}")
            return False
        
        self.config.add_log_path(log_path)
        
        # Initialize position for new file
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(0, 2)  # Go to end
                self.log_positions[log_path] = f.tell()
        except Exception as e:
            self.logger.error(f"Error initializing position for {log_path}: {e}")
            return False
        
        self.logger.info(f"Added log file to monitoring: {log_path}")
        return True
    
    def remove_log_file(self, log_path: str):
        """Remove a log file from monitoring"""
        self.config.remove_log_path(log_path)
        if log_path in self.log_positions:
            del self.log_positions[log_path]
        self.logger.info(f"Removed log file from monitoring: {log_path}")
    
    def get_recent_events(self, hours: int = 24) -> List[SecurityEvent]:
        """Get recent security events"""
        return self.database.get_recent_events(hours)
    
    def analyze_ip(self, ip_address: str, hours: int = 24) -> Dict:
        """Get detailed analysis for a specific IP"""
        return self.threat_analyzer.get_ip_analysis(ip_address, hours)
