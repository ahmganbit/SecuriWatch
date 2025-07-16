"""
SecurityWatch Pro - Anomaly Detection Engine
Advanced behavioral analysis and anomaly detection using machine learning
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import joblib
import logging
from pathlib import Path

from ..models.events import SecurityEvent
from ..core.database import SecurityDatabase


class AnomalyDetector:
    """Advanced anomaly detection using machine learning"""
    
    def __init__(self, database: SecurityDatabase, model_path: str = "models/anomaly"):
        self.database = database
        self.model_path = Path(model_path)
        self.model_path.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger('SecurityWatch.AI.AnomalyDetector')
        
        # ML Models
        self.isolation_forest = None
        self.scaler = StandardScaler()
        self.dbscan = None
        
        # Behavioral baselines
        self.baseline_features = {}
        self.is_trained = False
        
        # Load existing models if available
        self._load_models()
    
    def extract_features(self, events: List[SecurityEvent]) -> pd.DataFrame:
        """Extract features from security events for ML analysis"""
        if not events:
            return pd.DataFrame()
        
        features = []
        
        # Group events by time windows and IPs
        df = pd.DataFrame([{
            'timestamp': event.timestamp,
            'source_ip': event.source_ip,
            'event_type': event.event_type,
            'severity': event.severity,
            'username': event.username
        } for event in events])
        
        # Convert timestamp to datetime if needed
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        
        # Feature extraction per IP
        for ip in df['source_ip'].unique():
            if not ip:
                continue
                
            ip_events = df[df['source_ip'] == ip]
            
            # Time-based features
            time_span = (ip_events['timestamp'].max() - ip_events['timestamp'].min()).total_seconds()
            event_frequency = len(ip_events) / max(time_span / 3600, 0.1)  # events per hour
            
            # Event type diversity
            unique_event_types = ip_events['event_type'].nunique()
            unique_usernames = ip_events['username'].nunique()
            
            # Severity distribution
            severity_counts = ip_events['severity'].value_counts()
            critical_ratio = severity_counts.get('critical', 0) / len(ip_events)
            high_ratio = severity_counts.get('high', 0) / len(ip_events)
            
            # Time pattern analysis
            hour_spread = ip_events['hour'].nunique()
            day_spread = ip_events['day_of_week'].nunique()
            
            # Sequential pattern analysis
            time_diffs = ip_events['timestamp'].diff().dt.total_seconds().fillna(0)
            avg_time_between_events = time_diffs.mean()
            time_variance = time_diffs.var()
            
            # Burst detection
            burst_threshold = 60  # seconds
            burst_events = (time_diffs < burst_threshold).sum()
            burst_ratio = burst_events / len(ip_events)
            
            features.append({
                'source_ip': ip,
                'total_events': len(ip_events),
                'event_frequency': event_frequency,
                'time_span_hours': time_span / 3600,
                'unique_event_types': unique_event_types,
                'unique_usernames': unique_usernames,
                'critical_ratio': critical_ratio,
                'high_ratio': high_ratio,
                'hour_spread': hour_spread,
                'day_spread': day_spread,
                'avg_time_between_events': avg_time_between_events,
                'time_variance': time_variance,
                'burst_ratio': burst_ratio,
                'is_weekend': ip_events['day_of_week'].iloc[0] >= 5,
                'is_night_time': (ip_events['hour'] < 6).any() or (ip_events['hour'] > 22).any()
            })
        
        return pd.DataFrame(features)
    
    def train_models(self, training_days: int = 30):
        """Train anomaly detection models on historical data"""
        self.logger.info(f"Training anomaly detection models on {training_days} days of data...")
        
        # Get training data
        cutoff_date = datetime.now() - timedelta(days=training_days)
        events = self.database.get_recent_events(training_days * 24)
        
        if len(events) < 100:
            self.logger.warning("Insufficient training data. Need at least 100 events.")
            return False
        
        # Extract features
        features_df = self.extract_features(events)
        if features_df.empty:
            self.logger.error("No features extracted from training data")
            return False
        
        # Prepare feature matrix
        feature_columns = [col for col in features_df.columns if col != 'source_ip']
        X = features_df[feature_columns].fillna(0)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Isolation Forest for anomaly detection
        self.isolation_forest = IsolationForest(
            contamination=0.1,  # Expect 10% anomalies
            random_state=42,
            n_estimators=100
        )
        self.isolation_forest.fit(X_scaled)
        
        # Train DBSCAN for clustering normal behavior
        self.dbscan = DBSCAN(eps=0.5, min_samples=5)
        self.dbscan.fit(X_scaled)
        
        # Calculate baseline statistics
        self.baseline_features = {
            'mean': X.mean().to_dict(),
            'std': X.std().to_dict(),
            'quantiles': {
                '25': X.quantile(0.25).to_dict(),
                '50': X.quantile(0.50).to_dict(),
                '75': X.quantile(0.75).to_dict(),
                '95': X.quantile(0.95).to_dict()
            }
        }
        
        self.is_trained = True
        self._save_models()
        
        self.logger.info("Anomaly detection models trained successfully")
        return True
    
    def detect_anomalies(self, events: List[SecurityEvent]) -> List[Dict]:
        """Detect anomalies in security events"""
        if not self.is_trained:
            self.logger.warning("Models not trained. Training on available data...")
            if not self.train_models():
                return []
        
        # Extract features
        features_df = self.extract_features(events)
        if features_df.empty:
            return []
        
        feature_columns = [col for col in features_df.columns if col != 'source_ip']
        X = features_df[feature_columns].fillna(0)
        X_scaled = self.scaler.transform(X)
        
        # Detect anomalies using Isolation Forest
        anomaly_scores = self.isolation_forest.decision_function(X_scaled)
        is_anomaly = self.isolation_forest.predict(X_scaled) == -1
        
        # Get cluster assignments
        cluster_labels = self.dbscan.fit_predict(X_scaled)
        
        anomalies = []
        for idx, (_, row) in enumerate(features_df.iterrows()):
            if is_anomaly[idx]:
                # Calculate anomaly details
                anomaly_score = anomaly_scores[idx]
                cluster_label = cluster_labels[idx]
                
                # Determine anomaly type
                anomaly_type = self._classify_anomaly_type(row, feature_columns)
                
                # Calculate confidence
                confidence = min(abs(anomaly_score) * 100, 100)
                
                anomalies.append({
                    'source_ip': row['source_ip'],
                    'anomaly_score': float(anomaly_score),
                    'confidence': float(confidence),
                    'anomaly_type': anomaly_type,
                    'cluster_label': int(cluster_label),
                    'features': row[feature_columns].to_dict(),
                    'severity': self._calculate_anomaly_severity(anomaly_score, row),
                    'description': self._generate_anomaly_description(anomaly_type, row),
                    'detected_at': datetime.now().isoformat()
                })
        
        self.logger.info(f"Detected {len(anomalies)} anomalies")
        return anomalies
    
    def _classify_anomaly_type(self, features: pd.Series, feature_columns: List[str]) -> str:
        """Classify the type of anomaly based on feature deviations"""
        baseline = self.baseline_features
        
        # Calculate z-scores for each feature
        z_scores = {}
        for col in feature_columns:
            if col in baseline['mean'] and baseline['std'][col] > 0:
                z_scores[col] = abs(features[col] - baseline['mean'][col]) / baseline['std'][col]
        
        # Find the most deviant features
        max_deviation = max(z_scores.values()) if z_scores else 0
        deviant_features = [k for k, v in z_scores.items() if v > 2.0]  # 2 standard deviations
        
        # Classify based on deviant features
        if 'event_frequency' in deviant_features and features['event_frequency'] > baseline['quantiles']['95']['event_frequency']:
            return 'high_frequency_attack'
        elif 'burst_ratio' in deviant_features and features['burst_ratio'] > 0.5:
            return 'burst_attack'
        elif 'unique_event_types' in deviant_features and features['unique_event_types'] > baseline['quantiles']['95']['unique_event_types']:
            return 'diverse_attack_pattern'
        elif 'critical_ratio' in deviant_features and features['critical_ratio'] > 0.3:
            return 'high_severity_pattern'
        elif features.get('is_night_time', False) and 'total_events' in deviant_features:
            return 'off_hours_activity'
        elif 'time_variance' in deviant_features and features['time_variance'] < baseline['quantiles']['25']['time_variance']:
            return 'automated_attack'
        else:
            return 'behavioral_anomaly'
    
    def _calculate_anomaly_severity(self, anomaly_score: float, features: pd.Series) -> str:
        """Calculate severity based on anomaly score and features"""
        score_abs = abs(anomaly_score)
        
        if score_abs > 0.5 or features.get('critical_ratio', 0) > 0.5:
            return 'critical'
        elif score_abs > 0.3 or features.get('high_ratio', 0) > 0.3:
            return 'high'
        elif score_abs > 0.1:
            return 'medium'
        else:
            return 'low'
    
    def _generate_anomaly_description(self, anomaly_type: str, features: pd.Series) -> str:
        """Generate human-readable description of the anomaly"""
        descriptions = {
            'high_frequency_attack': f"Unusually high event frequency ({features['event_frequency']:.1f} events/hour) from {features['source_ip']}",
            'burst_attack': f"Burst attack pattern detected with {features['burst_ratio']:.1%} of events in rapid succession",
            'diverse_attack_pattern': f"Diverse attack pattern with {features['unique_event_types']} different event types",
            'high_severity_pattern': f"High severity event pattern with {features['critical_ratio']:.1%} critical events",
            'off_hours_activity': f"Suspicious off-hours activity with {features['total_events']} events",
            'automated_attack': f"Automated attack pattern detected with consistent timing intervals",
            'behavioral_anomaly': f"Behavioral anomaly detected in activity pattern"
        }
        return descriptions.get(anomaly_type, f"Anomalous behavior detected from {features['source_ip']}")
    
    def _save_models(self):
        """Save trained models to disk"""
        try:
            if self.isolation_forest:
                joblib.dump(self.isolation_forest, self.model_path / 'isolation_forest.pkl')
            if self.scaler:
                joblib.dump(self.scaler, self.model_path / 'scaler.pkl')
            if self.baseline_features:
                joblib.dump(self.baseline_features, self.model_path / 'baseline_features.pkl')
            
            # Save metadata
            metadata = {
                'trained_at': datetime.now().isoformat(),
                'is_trained': self.is_trained
            }
            joblib.dump(metadata, self.model_path / 'metadata.pkl')
            
            self.logger.info("Models saved successfully")
        except Exception as e:
            self.logger.error(f"Error saving models: {e}")
    
    def _load_models(self):
        """Load trained models from disk"""
        try:
            if (self.model_path / 'isolation_forest.pkl').exists():
                self.isolation_forest = joblib.load(self.model_path / 'isolation_forest.pkl')
            if (self.model_path / 'scaler.pkl').exists():
                self.scaler = joblib.load(self.model_path / 'scaler.pkl')
            if (self.model_path / 'baseline_features.pkl').exists():
                self.baseline_features = joblib.load(self.model_path / 'baseline_features.pkl')
            if (self.model_path / 'metadata.pkl').exists():
                metadata = joblib.load(self.model_path / 'metadata.pkl')
                self.is_trained = metadata.get('is_trained', False)
            
            if self.is_trained:
                self.logger.info("Models loaded successfully")
        except Exception as e:
            self.logger.error(f"Error loading models: {e}")
            self.is_trained = False
    
    def get_model_info(self) -> Dict:
        """Get information about the trained models"""
        return {
            'is_trained': self.is_trained,
            'model_path': str(self.model_path),
            'has_isolation_forest': self.isolation_forest is not None,
            'has_scaler': self.scaler is not None,
            'has_baseline': bool(self.baseline_features),
            'baseline_features': list(self.baseline_features.get('mean', {}).keys()) if self.baseline_features else []
        }
