"""
SecurityWatch Pro - Database Management
"""

import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import List

from ..models.events import SecurityEvent


class SecurityDatabase:
    """SQLite database for storing security events"""
    
    def __init__(self, db_path: str = "securitywatch.db"):
        self.db_path = Path(db_path)
        self.init_database()
    
    def init_database(self):
        """Initialize database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source_ip TEXT,
                username TEXT,
                hostname TEXT,
                details TEXT,
                severity TEXT NOT NULL,
                log_source TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Threat patterns table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                pattern TEXT NOT NULL,
                severity TEXT NOT NULL,
                threshold_count INTEGER DEFAULT 5,
                time_window INTEGER DEFAULT 300,
                enabled BOOLEAN DEFAULT 1,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # IP reputation table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_reputation (
                ip_address TEXT PRIMARY KEY,
                reputation_score INTEGER DEFAULT 0,
                first_seen TEXT,
                last_seen TEXT,
                event_count INTEGER DEFAULT 0,
                is_blocked BOOLEAN DEFAULT 0
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def add_event(self, event: SecurityEvent):
        """Add security event to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO security_events 
            (timestamp, event_type, source_ip, username, hostname, details, severity, log_source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event.timestamp.isoformat(),
            event.event_type,
            event.source_ip,
            event.username,
            event.hostname,
            event.details,
            event.severity,
            event.log_source
        ))
        
        conn.commit()
        conn.close()
    
    def get_recent_events(self, hours: int = 24) -> List[SecurityEvent]:
        """Get events from the last N hours"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        since = datetime.now() - timedelta(hours=hours)
        cursor.execute('''
            SELECT timestamp, event_type, source_ip, username, hostname, details, severity, log_source
            FROM security_events 
            WHERE timestamp > ?
            ORDER BY timestamp DESC
        ''', (since.isoformat(),))
        
        events = []
        for row in cursor.fetchall():
            events.append(SecurityEvent(
                timestamp=datetime.fromisoformat(row[0]),
                event_type=row[1],
                source_ip=row[2] or "",
                username=row[3] or "",
                hostname=row[4] or "",
                details=row[5] or "",
                severity=row[6],
                log_source=row[7] or ""
            ))
        
        conn.close()
        return events
    
    def update_ip_reputation(self, ip: str, severity: str):
        """Update IP reputation based on events"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Score mapping
        score_map = {"low": 1, "medium": 5, "high": 10, "critical": 20}
        score = score_map.get(severity, 1)
        
        cursor.execute('''
            INSERT OR REPLACE INTO ip_reputation 
            (ip_address, reputation_score, first_seen, last_seen, event_count, is_blocked)
            VALUES (
                ?, 
                COALESCE((SELECT reputation_score FROM ip_reputation WHERE ip_address = ?), 0) + ?,
                COALESCE((SELECT first_seen FROM ip_reputation WHERE ip_address = ?), ?),
                ?,
                COALESCE((SELECT event_count FROM ip_reputation WHERE ip_address = ?), 0) + 1,
                CASE WHEN COALESCE((SELECT reputation_score FROM ip_reputation WHERE ip_address = ?), 0) + ? > 50 THEN 1 ELSE 0 END
            )
        ''', (ip, ip, score, ip, datetime.now().isoformat(), datetime.now().isoformat(), ip, ip, score))
        
        conn.commit()
        conn.close()
    
    def cleanup_old_events(self, days: int):
        """Remove events older than specified days"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cutoff = datetime.now() - timedelta(days=days)
        cursor.execute('DELETE FROM security_events WHERE timestamp < ?', (cutoff.isoformat(),))
        
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        
        return deleted
    
    def get_statistics(self) -> dict:
        """Get database statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        # Total events
        cursor.execute('SELECT COUNT(*) FROM security_events')
        stats['total_events'] = cursor.fetchone()[0]
        
        # Events by severity
        cursor.execute('SELECT severity, COUNT(*) FROM security_events GROUP BY severity')
        stats['by_severity'] = dict(cursor.fetchall())
        
        # Top IPs
        cursor.execute('''
            SELECT source_ip, COUNT(*) as count 
            FROM security_events 
            WHERE source_ip != "" 
            GROUP BY source_ip 
            ORDER BY count DESC 
            LIMIT 10
        ''')
        stats['top_ips'] = cursor.fetchall()
        
        conn.close()
        return stats
