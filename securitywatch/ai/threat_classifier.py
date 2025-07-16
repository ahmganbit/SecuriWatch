"""
SecurityWatch Pro - AI Threat Classification Engine
Advanced threat classification using machine learning and threat intelligence
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
import logging
from pathlib import Path

from ..models.events import SecurityEvent
from ..core.database import SecurityDatabase


class ThreatClassifier:
    """AI-powered threat classification and severity prediction"""
    
    def __init__(self, database: SecurityDatabase, model_path: str = "models/classifier"):
        self.database = database
        self.model_path = Path(model_path)
        self.model_path.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger('SecurityWatch.AI.ThreatClassifier')
        
        # ML Models
        self.threat_classifier = None
        self.severity_classifier = None
        self.feature_scaler = StandardScaler()
        self.label_encoders = {}
        
        # Threat intelligence
        self.threat_signatures = self._load_threat_signatures()
        self.is_trained = False
        
        # Load existing models
        self._load_models()
    
    def _load_threat_signatures(self) -> Dict:
        """Load threat intelligence signatures"""
        return {
            'malware_families': {
                'mirai': ['admin', 'root', '123456', 'password'],
                'conficker': ['administrator', 'guest', 'user'],
                'zeus': ['bank', 'login', 'secure'],
                'stuxnet': ['siemens', 'scada', 'plc']
            },
            'attack_patterns': {
                'credential_stuffing': {
                    'indicators': ['multiple_usernames', 'high_frequency', 'distributed_ips'],
                    'severity_multiplier': 1.5
                },
                'sql_injection': {
                    'indicators': ['union', 'select', 'drop', 'insert', 'delete'],
                    'severity_multiplier': 2.0
                },
                'directory_traversal': {
                    'indicators': ['../', '..\\', '%2e%2e'],
                    'severity_multiplier': 1.8
                },
                'command_injection': {
                    'indicators': ['|', ';', '&&', '`', '$()'],
                    'severity_multiplier': 2.2
                }
            },
            'threat_actors': {
                'apt_groups': {
                    'apt1': ['china', 'pla', 'comment_crew'],
                    'lazarus': ['north_korea', 'sony', 'wannacry'],
                    'fancy_bear': ['russia', 'gru', 'apt28']
                }
            }
        }
    
    def extract_threat_features(self, events: List[SecurityEvent]) -> pd.DataFrame:
        """Extract advanced features for threat classification"""
        if not events:
            return pd.DataFrame()
        
        features = []
        
        for event in events:
            # Basic features
            feature_dict = {
                'event_type': event.event_type,
                'severity': event.severity,
                'source_ip': event.source_ip,
                'username': event.username or 'unknown',
                'hour': event.timestamp.hour,
                'day_of_week': event.timestamp.weekday(),
                'is_weekend': event.timestamp.weekday() >= 5,
                'is_night': event.timestamp.hour < 6 or event.timestamp.hour > 22
            }
            
            # Advanced threat intelligence features
            feature_dict.update(self._extract_threat_intelligence_features(event))
            
            # Behavioral features
            feature_dict.update(self._extract_behavioral_features(event, events))
            
            # Network features
            feature_dict.update(self._extract_network_features(event))
            
            features.append(feature_dict)
        
        return pd.DataFrame(features)
    
    def _extract_threat_intelligence_features(self, event: SecurityEvent) -> Dict:
        """Extract threat intelligence features"""
        features = {}
        details = event.details.lower()
        
        # Malware family indicators
        malware_score = 0
        for family, indicators in self.threat_signatures['malware_families'].items():
            if any(indicator in details for indicator in indicators):
                malware_score += 1
                features[f'malware_{family}'] = 1
            else:
                features[f'malware_{family}'] = 0
        
        features['malware_indicators'] = malware_score
        
        # Attack pattern indicators
        attack_pattern_score = 0
        for pattern, data in self.threat_signatures['attack_patterns'].items():
            if any(indicator in details for indicator in data['indicators']):
                attack_pattern_score += data['severity_multiplier']
                features[f'attack_{pattern}'] = 1
            else:
                features[f'attack_{pattern}'] = 0
        
        features['attack_pattern_score'] = attack_pattern_score
        
        # Suspicious keywords
        suspicious_keywords = [
            'hack', 'exploit', 'payload', 'shell', 'backdoor',
            'trojan', 'virus', 'malware', 'botnet', 'ransomware'
        ]
        features['suspicious_keywords'] = sum(1 for keyword in suspicious_keywords if keyword in details)
        
        # Encoding techniques
        encoding_indicators = ['%', 'base64', 'hex', 'unicode', 'url']
        features['encoding_indicators'] = sum(1 for indicator in encoding_indicators if indicator in details)
        
        return features
    
    def _extract_behavioral_features(self, event: SecurityEvent, all_events: List[SecurityEvent]) -> Dict:
        """Extract behavioral analysis features"""
        features = {}
        
        # Find related events from same IP
        same_ip_events = [e for e in all_events if e.source_ip == event.source_ip]
        
        if len(same_ip_events) > 1:
            # Time-based patterns
            timestamps = [e.timestamp for e in same_ip_events]
            timestamps.sort()
            
            time_diffs = [(timestamps[i+1] - timestamps[i]).total_seconds() 
                         for i in range(len(timestamps)-1)]
            
            features['avg_time_between_events'] = np.mean(time_diffs) if time_diffs else 0
            features['time_variance'] = np.var(time_diffs) if time_diffs else 0
            features['is_rhythmic'] = 1 if features['time_variance'] < 10 else 0  # Very consistent timing
            
            # Event diversity
            event_types = [e.event_type for e in same_ip_events]
            features['event_type_diversity'] = len(set(event_types))
            features['repeat_event_ratio'] = event_types.count(event.event_type) / len(event_types)
            
            # Username patterns
            usernames = [e.username for e in same_ip_events if e.username]
            features['username_diversity'] = len(set(usernames)) if usernames else 0
            features['username_attempts'] = len(usernames)
            
            # Escalation pattern
            severities = [e.severity for e in same_ip_events]
            severity_scores = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
            severity_trend = [severity_scores.get(s, 0) for s in severities]
            features['severity_escalation'] = 1 if len(severity_trend) > 1 and severity_trend[-1] > severity_trend[0] else 0
        else:
            # Single event features
            features.update({
                'avg_time_between_events': 0,
                'time_variance': 0,
                'is_rhythmic': 0,
                'event_type_diversity': 1,
                'repeat_event_ratio': 1,
                'username_diversity': 1 if event.username else 0,
                'username_attempts': 1 if event.username else 0,
                'severity_escalation': 0
            })
        
        return features
    
    def _extract_network_features(self, event: SecurityEvent) -> Dict:
        """Extract network-based features"""
        features = {}
        
        if event.source_ip:
            ip_parts = event.source_ip.split('.')
            if len(ip_parts) == 4:
                try:
                    # IP classification
                    first_octet = int(ip_parts[0])
                    features['is_private_ip'] = 1 if first_octet in [10, 172, 192] else 0
                    features['is_localhost'] = 1 if event.source_ip.startswith('127.') else 0
                    features['is_multicast'] = 1 if 224 <= first_octet <= 239 else 0
                    
                    # Geographic indicators (simplified)
                    features['ip_first_octet'] = first_octet
                    features['is_suspicious_range'] = 1 if first_octet in [1, 2, 5, 14, 23, 27, 31] else 0
                    
                except ValueError:
                    features.update({
                        'is_private_ip': 0, 'is_localhost': 0, 'is_multicast': 0,
                        'ip_first_octet': 0, 'is_suspicious_range': 0
                    })
            else:
                features.update({
                    'is_private_ip': 0, 'is_localhost': 0, 'is_multicast': 0,
                    'ip_first_octet': 0, 'is_suspicious_range': 0
                })
        else:
            features.update({
                'is_private_ip': 0, 'is_localhost': 0, 'is_multicast': 0,
                'ip_first_octet': 0, 'is_suspicious_range': 0
            })
        
        return features
    
    def train_classifiers(self, training_days: int = 60):
        """Train threat classification models"""
        self.logger.info(f"Training threat classifiers on {training_days} days of data...")
        
        # Get training data
        events = self.database.get_recent_events(training_days * 24)
        
        if len(events) < 200:
            self.logger.warning("Insufficient training data. Need at least 200 events.")
            return False
        
        # Extract features
        features_df = self.extract_threat_features(events)
        if features_df.empty:
            self.logger.error("No features extracted from training data")
            return False
        
        # Prepare data for training
        X, y_threat, y_severity = self._prepare_training_data(features_df)
        
        if X.empty:
            self.logger.error("No valid training data prepared")
            return False
        
        # Split data
        X_train, X_test, y_threat_train, y_threat_test, y_severity_train, y_severity_test = train_test_split(
            X, y_threat, y_severity, test_size=0.2, random_state=42, stratify=y_threat
        )
        
        # Scale features
        X_train_scaled = self.feature_scaler.fit_transform(X_train)
        X_test_scaled = self.feature_scaler.transform(X_test)
        
        # Train threat type classifier
        self.threat_classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        )
        self.threat_classifier.fit(X_train_scaled, y_threat_train)
        
        # Train severity classifier
        self.severity_classifier = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=6,
            random_state=42
        )
        self.severity_classifier.fit(X_train_scaled, y_severity_train)
        
        # Evaluate models
        threat_pred = self.threat_classifier.predict(X_test_scaled)
        severity_pred = self.severity_classifier.predict(X_test_scaled)
        
        threat_accuracy = accuracy_score(y_threat_test, threat_pred)
        severity_accuracy = accuracy_score(y_severity_test, severity_pred)
        
        self.logger.info(f"Threat classifier accuracy: {threat_accuracy:.3f}")
        self.logger.info(f"Severity classifier accuracy: {severity_accuracy:.3f}")
        
        self.is_trained = True
        self._save_models()
        
        return True
    
    def _prepare_training_data(self, features_df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series, pd.Series]:
        """Prepare training data with labels"""
        # Create threat type labels based on event types and features
        threat_labels = []
        severity_labels = []
        
        for _, row in features_df.iterrows():
            # Determine threat type
            if row.get('attack_sql_injection', 0) or 'injection' in row['event_type']:
                threat_type = 'injection_attack'
            elif row.get('attack_credential_stuffing', 0) or 'failed_login' in row['event_type']:
                threat_type = 'credential_attack'
            elif row.get('attack_directory_traversal', 0) or 'traversal' in row['event_type']:
                threat_type = 'path_traversal'
            elif row.get('attack_command_injection', 0) or 'command' in row['event_type']:
                threat_type = 'command_injection'
            elif row.get('malware_indicators', 0) > 0:
                threat_type = 'malware_activity'
            elif row.get('is_rhythmic', 0) and row.get('event_type_diversity', 0) > 3:
                threat_type = 'automated_attack'
            elif row.get('username_diversity', 0) > 5:
                threat_type = 'brute_force'
            else:
                threat_type = 'suspicious_activity'
            
            threat_labels.append(threat_type)
            severity_labels.append(row['severity'])
        
        # Encode categorical variables
        categorical_columns = ['event_type', 'username']
        for col in categorical_columns:
            if col in features_df.columns:
                if col not in self.label_encoders:
                    self.label_encoders[col] = LabelEncoder()
                features_df[col] = self.label_encoders[col].fit_transform(features_df[col].astype(str))
        
        # Select numeric features for training
        numeric_columns = features_df.select_dtypes(include=[np.number]).columns
        X = features_df[numeric_columns]
        
        return X, pd.Series(threat_labels), pd.Series(severity_labels)
    
    def classify_threats(self, events: List[SecurityEvent]) -> List[Dict]:
        """Classify threats in security events"""
        if not self.is_trained:
            self.logger.warning("Classifiers not trained. Training on available data...")
            if not self.train_classifiers():
                return []
        
        # Extract features
        features_df = self.extract_threat_features(events)
        if features_df.empty:
            return []
        
        # Prepare features for prediction
        X = self._prepare_features_for_prediction(features_df)
        if X.empty:
            return []
        
        X_scaled = self.feature_scaler.transform(X)
        
        # Make predictions
        threat_predictions = self.threat_classifier.predict(X_scaled)
        threat_probabilities = self.threat_classifier.predict_proba(X_scaled)
        severity_predictions = self.severity_classifier.predict(X_scaled)
        severity_probabilities = self.severity_classifier.predict_proba(X_scaled)
        
        # Compile results
        classifications = []
        for idx, event in enumerate(events):
            threat_type = threat_predictions[idx]
            threat_confidence = np.max(threat_probabilities[idx]) * 100
            
            severity = severity_predictions[idx]
            severity_confidence = np.max(severity_probabilities[idx]) * 100
            
            classifications.append({
                'event_id': f"{event.source_ip}_{event.timestamp.isoformat()}",
                'source_ip': event.source_ip,
                'original_event_type': event.event_type,
                'predicted_threat_type': threat_type,
                'threat_confidence': float(threat_confidence),
                'predicted_severity': severity,
                'severity_confidence': float(severity_confidence),
                'risk_score': self._calculate_risk_score(threat_type, severity, threat_confidence),
                'recommendations': self._generate_recommendations(threat_type, severity),
                'classified_at': datetime.now().isoformat()
            })
        
        return classifications
    
    def _prepare_features_for_prediction(self, features_df: pd.DataFrame) -> pd.DataFrame:
        """Prepare features for prediction"""
        # Encode categorical variables using existing encoders
        for col, encoder in self.label_encoders.items():
            if col in features_df.columns:
                # Handle unseen categories
                features_df[col] = features_df[col].astype(str)
                known_classes = set(encoder.classes_)
                features_df[col] = features_df[col].apply(
                    lambda x: x if x in known_classes else 'unknown'
                )
                
                # Add 'unknown' to encoder if not present
                if 'unknown' not in known_classes:
                    encoder.classes_ = np.append(encoder.classes_, 'unknown')
                
                features_df[col] = encoder.transform(features_df[col])
        
        # Select numeric features
        numeric_columns = features_df.select_dtypes(include=[np.number]).columns
        return features_df[numeric_columns]
    
    def _calculate_risk_score(self, threat_type: str, severity: str, confidence: float) -> float:
        """Calculate overall risk score"""
        threat_weights = {
            'injection_attack': 0.9,
            'command_injection': 0.85,
            'malware_activity': 0.8,
            'brute_force': 0.7,
            'automated_attack': 0.6,
            'credential_attack': 0.65,
            'path_traversal': 0.75,
            'suspicious_activity': 0.4
        }
        
        severity_weights = {
            'critical': 1.0,
            'high': 0.8,
            'medium': 0.6,
            'low': 0.3
        }
        
        threat_weight = threat_weights.get(threat_type, 0.5)
        severity_weight = severity_weights.get(severity, 0.5)
        confidence_weight = confidence / 100
        
        risk_score = (threat_weight * 0.4 + severity_weight * 0.4 + confidence_weight * 0.2) * 100
        return min(risk_score, 100)
    
    def _generate_recommendations(self, threat_type: str, severity: str) -> List[str]:
        """Generate security recommendations based on threat classification"""
        recommendations = {
            'injection_attack': [
                "Implement input validation and parameterized queries",
                "Deploy Web Application Firewall (WAF)",
                "Review and patch application vulnerabilities"
            ],
            'command_injection': [
                "Sanitize user inputs and disable dangerous functions",
                "Implement strict access controls",
                "Monitor system command execution"
            ],
            'malware_activity': [
                "Run full antivirus scan on affected systems",
                "Isolate infected systems from network",
                "Update security signatures and patches"
            ],
            'brute_force': [
                "Implement account lockout policies",
                "Enable multi-factor authentication",
                "Block attacking IP addresses"
            ],
            'automated_attack': [
                "Implement rate limiting and CAPTCHA",
                "Deploy behavioral analysis tools",
                "Monitor for bot-like activity patterns"
            ]
        }
        
        base_recommendations = recommendations.get(threat_type, [
            "Monitor the situation closely",
            "Review security logs for related activity",
            "Consider blocking suspicious IP addresses"
        ])
        
        if severity in ['critical', 'high']:
            base_recommendations.insert(0, "URGENT: Immediate security response required")
        
        return base_recommendations
    
    def _save_models(self):
        """Save trained models to disk"""
        try:
            if self.threat_classifier:
                joblib.dump(self.threat_classifier, self.model_path / 'threat_classifier.pkl')
            if self.severity_classifier:
                joblib.dump(self.severity_classifier, self.model_path / 'severity_classifier.pkl')
            if self.feature_scaler:
                joblib.dump(self.feature_scaler, self.model_path / 'feature_scaler.pkl')
            if self.label_encoders:
                joblib.dump(self.label_encoders, self.model_path / 'label_encoders.pkl')
            
            metadata = {
                'trained_at': datetime.now().isoformat(),
                'is_trained': self.is_trained,
                'threat_signatures_version': '1.0'
            }
            joblib.dump(metadata, self.model_path / 'classifier_metadata.pkl')
            
            self.logger.info("Threat classifiers saved successfully")
        except Exception as e:
            self.logger.error(f"Error saving classifiers: {e}")
    
    def _load_models(self):
        """Load trained models from disk"""
        try:
            if (self.model_path / 'threat_classifier.pkl').exists():
                self.threat_classifier = joblib.load(self.model_path / 'threat_classifier.pkl')
            if (self.model_path / 'severity_classifier.pkl').exists():
                self.severity_classifier = joblib.load(self.model_path / 'severity_classifier.pkl')
            if (self.model_path / 'feature_scaler.pkl').exists():
                self.feature_scaler = joblib.load(self.model_path / 'feature_scaler.pkl')
            if (self.model_path / 'label_encoders.pkl').exists():
                self.label_encoders = joblib.load(self.model_path / 'label_encoders.pkl')
            if (self.model_path / 'classifier_metadata.pkl').exists():
                metadata = joblib.load(self.model_path / 'classifier_metadata.pkl')
                self.is_trained = metadata.get('is_trained', False)
            
            if self.is_trained:
                self.logger.info("Threat classifiers loaded successfully")
        except Exception as e:
            self.logger.error(f"Error loading classifiers: {e}")
            self.is_trained = False
