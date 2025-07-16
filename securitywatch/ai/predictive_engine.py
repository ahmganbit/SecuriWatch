"""
SecurityWatch Pro - Predictive Security Engine
Predictive analytics for forecasting security threats and attack patterns
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional
from sklearn.ensemble import RandomForestRegressor
from sklearn.linear_model import LinearRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import mean_absolute_error, r2_score
import joblib
import logging
from pathlib import Path

from ..models.events import SecurityEvent
from ..core.database import SecurityDatabase


class PredictiveEngine:
    """Predictive analytics for security threat forecasting"""
    
    def __init__(self, database: SecurityDatabase, model_path: str = "models/predictive"):
        self.database = database
        self.model_path = Path(model_path)
        self.model_path.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger('SecurityWatch.AI.PredictiveEngine')
        
        # Prediction models
        self.threat_volume_model = None
        self.severity_trend_model = None
        self.attack_timing_model = None
        self.feature_scaler = StandardScaler()
        
        # Prediction parameters
        self.prediction_horizon_hours = 24
        self.training_window_days = 60
        self.min_training_samples = 100
        
        # Model performance metrics
        self.model_metrics = {}
        self.is_trained = False
        
        # Load existing models
        self._load_models()
    
    def prepare_time_series_features(self, events: List[SecurityEvent], 
                                   window_hours: int = 1) -> pd.DataFrame:
        """Prepare time series features for prediction models"""
        if not events:
            return pd.DataFrame()
        
        # Create time series dataframe
        df = pd.DataFrame([{
            'timestamp': event.timestamp,
            'severity': event.severity,
            'event_type': event.event_type,
            'source_ip': event.source_ip
        } for event in events])
        
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.sort_values('timestamp')
        
        # Create time windows
        start_time = df['timestamp'].min()
        end_time = df['timestamp'].max()
        
        time_windows = []
        current_time = start_time
        
        while current_time <= end_time:
            window_end = current_time + timedelta(hours=window_hours)
            
            # Filter events in this window
            window_events = df[
                (df['timestamp'] >= current_time) & 
                (df['timestamp'] < window_end)
            ]
            
            # Calculate features for this window
            features = self._calculate_window_features(window_events, current_time)
            time_windows.append(features)
            
            current_time = window_end
        
        return pd.DataFrame(time_windows)
    
    def _calculate_window_features(self, window_events: pd.DataFrame, 
                                 window_start: datetime) -> Dict:
        """Calculate features for a time window"""
        features = {
            'timestamp': window_start,
            'hour': window_start.hour,
            'day_of_week': window_start.weekday(),
            'is_weekend': window_start.weekday() >= 5,
            'is_business_hours': 9 <= window_start.hour <= 17,
            'is_night': window_start.hour < 6 or window_start.hour > 22
        }
        
        if len(window_events) == 0:
            # No events in this window
            features.update({
                'total_events': 0,
                'unique_ips': 0,
                'critical_events': 0,
                'high_events': 0,
                'medium_events': 0,
                'low_events': 0,
                'severity_score': 0,
                'event_type_diversity': 0,
                'ip_diversity': 0
            })
        else:
            # Calculate event-based features
            severity_counts = window_events['severity'].value_counts()
            event_types = window_events['event_type'].nunique()
            unique_ips = window_events['source_ip'].nunique()
            
            # Severity scoring
            severity_weights = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
            severity_score = sum(
                severity_weights.get(sev, 0) * count 
                for sev, count in severity_counts.items()
            )
            
            features.update({
                'total_events': len(window_events),
                'unique_ips': unique_ips,
                'critical_events': severity_counts.get('critical', 0),
                'high_events': severity_counts.get('high', 0),
                'medium_events': severity_counts.get('medium', 0),
                'low_events': severity_counts.get('low', 0),
                'severity_score': severity_score,
                'event_type_diversity': event_types,
                'ip_diversity': unique_ips
            })
        
        return features
    
    def train_prediction_models(self, training_days: int = None):
        """Train predictive models on historical data"""
        if training_days is None:
            training_days = self.training_window_days
            
        self.logger.info(f"Training predictive models on {training_days} days of data...")
        
        # Get training data
        events = self.database.get_recent_events(training_days * 24)
        
        if len(events) < self.min_training_samples:
            self.logger.warning(f"Insufficient training data. Need at least {self.min_training_samples} events.")
            return False
        
        # Prepare time series features
        features_df = self.prepare_time_series_features(events, window_hours=1)
        
        if len(features_df) < 24:  # Need at least 24 hours of data
            self.logger.error("Insufficient time series data for training")
            return False
        
        # Prepare training data
        X, y_volume, y_severity = self._prepare_prediction_training_data(features_df)
        
        if len(X) < 20:  # Need minimum samples for training
            self.logger.error("Insufficient samples for model training")
            return False
        
        # Scale features
        X_scaled = self.feature_scaler.fit_transform(X)
        
        # Train threat volume prediction model
        self.threat_volume_model = RandomForestRegressor(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        self.threat_volume_model.fit(X_scaled, y_volume)
        
        # Train severity trend prediction model
        self.severity_trend_model = RandomForestRegressor(
            n_estimators=100,
            max_depth=8,
            random_state=42
        )
        self.severity_trend_model.fit(X_scaled, y_severity)
        
        # Train attack timing model
        self.attack_timing_model = self._train_timing_model(features_df)
        
        # Evaluate models
        self._evaluate_models(X_scaled, y_volume, y_severity)
        
        self.is_trained = True
        self._save_models()
        
        self.logger.info("Predictive models trained successfully")
        return True
    
    def _prepare_prediction_training_data(self, features_df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Prepare training data for prediction models"""
        # Sort by timestamp
        features_df = features_df.sort_values('timestamp')
        
        # Create feature matrix
        feature_columns = [
            'hour', 'day_of_week', 'is_weekend', 'is_business_hours', 'is_night',
            'total_events', 'unique_ips', 'critical_events', 'high_events',
            'medium_events', 'low_events', 'event_type_diversity', 'ip_diversity'
        ]
        
        # Add lag features (previous time windows)
        for lag in [1, 2, 3, 6, 12, 24]:  # 1h, 2h, 3h, 6h, 12h, 24h ago
            if len(features_df) > lag:
                features_df[f'total_events_lag_{lag}'] = features_df['total_events'].shift(lag)
                features_df[f'severity_score_lag_{lag}'] = features_df['severity_score'].shift(lag)
                feature_columns.extend([f'total_events_lag_{lag}', f'severity_score_lag_{lag}'])
        
        # Add rolling averages
        for window in [3, 6, 12, 24]:  # 3h, 6h, 12h, 24h rolling averages
            features_df[f'total_events_rolling_{window}'] = features_df['total_events'].rolling(window).mean()
            features_df[f'severity_score_rolling_{window}'] = features_df['severity_score'].rolling(window).mean()
            feature_columns.extend([f'total_events_rolling_{window}', f'severity_score_rolling_{window}'])
        
        # Remove rows with NaN values (due to lag and rolling features)
        features_df = features_df.dropna()
        
        if len(features_df) < 20:
            return np.array([]), np.array([]), np.array([])
        
        # Prepare target variables (next hour predictions)
        y_volume = features_df['total_events'].shift(-1).dropna()  # Next hour event count
        y_severity = features_df['severity_score'].shift(-1).dropna()  # Next hour severity score
        
        # Align features with targets
        X = features_df[feature_columns].iloc[:-1]  # Remove last row to align with shifted targets
        
        return X.fillna(0).values, y_volume.values, y_severity.values
    
    def _train_timing_model(self, features_df: pd.DataFrame) -> Dict:
        """Train attack timing prediction model"""
        # Analyze attack patterns by time
        attack_patterns = {}
        
        # Group by hour and calculate attack probabilities
        hourly_stats = features_df.groupby('hour').agg({
            'total_events': ['mean', 'std', 'max'],
            'severity_score': ['mean', 'std', 'max'],
            'critical_events': 'mean'
        }).round(3)
        
        # Group by day of week
        daily_stats = features_df.groupby('day_of_week').agg({
            'total_events': ['mean', 'std', 'max'],
            'severity_score': ['mean', 'std', 'max'],
            'critical_events': 'mean'
        }).round(3)
        
        # Calculate attack probability scores
        max_events = features_df['total_events'].max()
        max_severity = features_df['severity_score'].max()
        
        hourly_risk = {}
        for hour in range(24):
            hour_data = features_df[features_df['hour'] == hour]
            if len(hour_data) > 0:
                avg_events = hour_data['total_events'].mean()
                avg_severity = hour_data['severity_score'].mean()
                
                # Normalize to 0-1 scale
                event_risk = avg_events / max_events if max_events > 0 else 0
                severity_risk = avg_severity / max_severity if max_severity > 0 else 0
                
                hourly_risk[hour] = (event_risk + severity_risk) / 2
            else:
                hourly_risk[hour] = 0
        
        return {
            'hourly_stats': hourly_stats.to_dict(),
            'daily_stats': daily_stats.to_dict(),
            'hourly_risk_scores': hourly_risk,
            'peak_attack_hours': sorted(hourly_risk.items(), key=lambda x: x[1], reverse=True)[:3],
            'model_type': 'statistical_timing_model'
        }
    
    def _evaluate_models(self, X: np.ndarray, y_volume: np.ndarray, y_severity: np.ndarray):
        """Evaluate model performance"""
        # Split data for evaluation
        split_idx = int(len(X) * 0.8)
        X_train, X_test = X[:split_idx], X[split_idx:]
        y_vol_train, y_vol_test = y_volume[:split_idx], y_volume[split_idx:]
        y_sev_train, y_sev_test = y_severity[:split_idx], y_severity[split_idx:]
        
        # Evaluate volume model
        vol_pred = self.threat_volume_model.predict(X_test)
        vol_mae = mean_absolute_error(y_vol_test, vol_pred)
        vol_r2 = r2_score(y_vol_test, vol_pred)
        
        # Evaluate severity model
        sev_pred = self.severity_trend_model.predict(X_test)
        sev_mae = mean_absolute_error(y_sev_test, sev_pred)
        sev_r2 = r2_score(y_sev_test, sev_pred)
        
        self.model_metrics = {
            'volume_model': {
                'mae': float(vol_mae),
                'r2_score': float(vol_r2),
                'accuracy_category': self._categorize_accuracy(vol_r2)
            },
            'severity_model': {
                'mae': float(sev_mae),
                'r2_score': float(sev_r2),
                'accuracy_category': self._categorize_accuracy(sev_r2)
            },
            'evaluation_date': datetime.now().isoformat(),
            'test_samples': len(X_test)
        }
        
        self.logger.info(f"Volume model R²: {vol_r2:.3f}, MAE: {vol_mae:.3f}")
        self.logger.info(f"Severity model R²: {sev_r2:.3f}, MAE: {sev_mae:.3f}")
    
    def _categorize_accuracy(self, r2_score: float) -> str:
        """Categorize model accuracy based on R² score"""
        if r2_score >= 0.8:
            return "excellent"
        elif r2_score >= 0.6:
            return "good"
        elif r2_score >= 0.4:
            return "fair"
        else:
            return "poor"
    
    def predict_threat_trends(self, hours_ahead: int = None) -> Dict:
        """Predict threat trends for the next N hours"""
        if not self.is_trained:
            self.logger.warning("Models not trained. Training on available data...")
            if not self.train_prediction_models():
                return {}
        
        if hours_ahead is None:
            hours_ahead = self.prediction_horizon_hours
        
        # Get recent data for context
        recent_events = self.database.get_recent_events(48)  # Last 48 hours for context
        features_df = self.prepare_time_series_features(recent_events, window_hours=1)
        
        if features_df.empty:
            return {}
        
        predictions = []
        current_time = datetime.now()
        
        # Generate predictions for each hour
        for hour_offset in range(1, hours_ahead + 1):
            prediction_time = current_time + timedelta(hours=hour_offset)
            
            # Prepare features for this prediction time
            prediction_features = self._prepare_prediction_features(
                features_df, prediction_time, hour_offset
            )
            
            if prediction_features is not None:
                # Scale features
                features_scaled = self.feature_scaler.transform([prediction_features])
                
                # Make predictions
                volume_pred = self.threat_volume_model.predict(features_scaled)[0]
                severity_pred = self.severity_trend_model.predict(features_scaled)[0]
                
                # Get timing-based risk assessment
                timing_risk = self._get_timing_risk(prediction_time)
                
                predictions.append({
                    'timestamp': prediction_time.isoformat(),
                    'hour_offset': hour_offset,
                    'predicted_event_volume': max(0, int(round(volume_pred))),
                    'predicted_severity_score': max(0, float(severity_pred)),
                    'timing_risk_score': timing_risk,
                    'overall_risk_level': self._calculate_risk_level(volume_pred, severity_pred, timing_risk),
                    'confidence': self._calculate_prediction_confidence(hour_offset)
                })
        
        # Generate summary and recommendations
        summary = self._generate_prediction_summary(predictions)
        
        return {
            'predictions': predictions,
            'summary': summary,
            'model_metrics': self.model_metrics,
            'generated_at': datetime.now().isoformat(),
            'prediction_horizon_hours': hours_ahead
        }
    
    def _prepare_prediction_features(self, features_df: pd.DataFrame, 
                                   prediction_time: datetime, hour_offset: int) -> Optional[np.ndarray]:
        """Prepare features for a specific prediction time"""
        # Get the most recent feature vector as base
        if features_df.empty:
            return None
        
        latest_features = features_df.iloc[-1].copy()
        
        # Update time-based features
        latest_features['hour'] = prediction_time.hour
        latest_features['day_of_week'] = prediction_time.weekday()
        latest_features['is_weekend'] = prediction_time.weekday() >= 5
        latest_features['is_business_hours'] = 9 <= prediction_time.hour <= 17
        latest_features['is_night'] = prediction_time.hour < 6 or prediction_time.hour > 22
        
        # Use recent values for lag features (simplified approach)
        # In a production system, you'd maintain a rolling window of recent predictions
        
        feature_columns = [
            'hour', 'day_of_week', 'is_weekend', 'is_business_hours', 'is_night',
            'total_events', 'unique_ips', 'critical_events', 'high_events',
            'medium_events', 'low_events', 'event_type_diversity', 'ip_diversity'
        ]
        
        # Add available lag and rolling features
        for col in latest_features.index:
            if 'lag_' in col or 'rolling_' in col:
                feature_columns.append(col)
        
        return latest_features[feature_columns].fillna(0).values
    
    def _get_timing_risk(self, prediction_time: datetime) -> float:
        """Get timing-based risk score"""
        if not self.attack_timing_model:
            return 0.5  # Default moderate risk
        
        hour = prediction_time.hour
        return self.attack_timing_model['hourly_risk_scores'].get(hour, 0.5)
    
    def _calculate_risk_level(self, volume_pred: float, severity_pred: float, timing_risk: float) -> str:
        """Calculate overall risk level"""
        # Normalize predictions (assuming reasonable ranges)
        volume_norm = min(volume_pred / 50, 1.0)  # Normalize assuming 50+ events is high
        severity_norm = min(severity_pred / 100, 1.0)  # Normalize assuming 100+ severity score is high
        
        # Weighted risk score
        risk_score = (volume_norm * 0.4 + severity_norm * 0.4 + timing_risk * 0.2)
        
        if risk_score >= 0.8:
            return "critical"
        elif risk_score >= 0.6:
            return "high"
        elif risk_score >= 0.4:
            return "medium"
        else:
            return "low"
    
    def _calculate_prediction_confidence(self, hour_offset: int) -> float:
        """Calculate prediction confidence based on time horizon"""
        # Confidence decreases with time horizon
        base_confidence = 0.9
        decay_rate = 0.05
        
        confidence = base_confidence * (1 - decay_rate * hour_offset)
        return max(0.3, min(1.0, confidence))  # Keep between 30% and 100%
    
    def _generate_prediction_summary(self, predictions: List[Dict]) -> Dict:
        """Generate summary of predictions"""
        if not predictions:
            return {}
        
        # Calculate summary statistics
        total_predicted_events = sum(p['predicted_event_volume'] for p in predictions)
        avg_severity = np.mean([p['predicted_severity_score'] for p in predictions])
        max_risk_hour = max(predictions, key=lambda x: x['timing_risk_score'])
        
        # Count risk levels
        risk_levels = [p['overall_risk_level'] for p in predictions]
        risk_counts = {level: risk_levels.count(level) for level in set(risk_levels)}
        
        # Generate alerts
        alerts = []
        if risk_counts.get('critical', 0) > 0:
            alerts.append(f"⚠️ {risk_counts['critical']} hours predicted with CRITICAL risk")
        if risk_counts.get('high', 0) > 2:
            alerts.append(f"📈 {risk_counts['high']} hours predicted with HIGH risk")
        
        return {
            'total_predicted_events': total_predicted_events,
            'average_severity_score': round(avg_severity, 2),
            'peak_risk_hour': max_risk_hour['timestamp'],
            'risk_level_distribution': risk_counts,
            'alerts': alerts,
            'recommendations': self._generate_predictive_recommendations(predictions)
        }
    
    def _generate_predictive_recommendations(self, predictions: List[Dict]) -> List[str]:
        """Generate recommendations based on predictions"""
        recommendations = []
        
        # Check for high-risk periods
        high_risk_hours = [p for p in predictions if p['overall_risk_level'] in ['critical', 'high']]
        
        if high_risk_hours:
            recommendations.append(f"🚨 Prepare for elevated threat activity in the next {len(high_risk_hours)} hours")
            recommendations.append("📋 Review incident response procedures and ensure staff availability")
        
        # Check for volume spikes
        max_volume = max(p['predicted_event_volume'] for p in predictions)
        if max_volume > 30:
            recommendations.append(f"📊 Prepare for high event volume (up to {max_volume} events/hour)")
            recommendations.append("🔧 Consider scaling monitoring infrastructure")
        
        # Check for timing patterns
        night_risks = [p for p in predictions if p['timing_risk_score'] > 0.7 and 
                      datetime.fromisoformat(p['timestamp']).hour in range(22, 6)]
        if night_risks:
            recommendations.append("🌙 Elevated risk during off-hours - ensure 24/7 monitoring coverage")
        
        return recommendations
    
    def _save_models(self):
        """Save trained models to disk"""
        try:
            if self.threat_volume_model:
                joblib.dump(self.threat_volume_model, self.model_path / 'threat_volume_model.pkl')
            if self.severity_trend_model:
                joblib.dump(self.severity_trend_model, self.model_path / 'severity_trend_model.pkl')
            if self.attack_timing_model:
                joblib.dump(self.attack_timing_model, self.model_path / 'attack_timing_model.pkl')
            if self.feature_scaler:
                joblib.dump(self.feature_scaler, self.model_path / 'predictive_scaler.pkl')
            
            metadata = {
                'trained_at': datetime.now().isoformat(),
                'is_trained': self.is_trained,
                'model_metrics': self.model_metrics,
                'prediction_horizon_hours': self.prediction_horizon_hours
            }
            joblib.dump(metadata, self.model_path / 'predictive_metadata.pkl')
            
            self.logger.info("Predictive models saved successfully")
        except Exception as e:
            self.logger.error(f"Error saving predictive models: {e}")
    
    def _load_models(self):
        """Load trained models from disk"""
        try:
            if (self.model_path / 'threat_volume_model.pkl').exists():
                self.threat_volume_model = joblib.load(self.model_path / 'threat_volume_model.pkl')
            if (self.model_path / 'severity_trend_model.pkl').exists():
                self.severity_trend_model = joblib.load(self.model_path / 'severity_trend_model.pkl')
            if (self.model_path / 'attack_timing_model.pkl').exists():
                self.attack_timing_model = joblib.load(self.model_path / 'attack_timing_model.pkl')
            if (self.model_path / 'predictive_scaler.pkl').exists():
                self.feature_scaler = joblib.load(self.model_path / 'predictive_scaler.pkl')
            if (self.model_path / 'predictive_metadata.pkl').exists():
                metadata = joblib.load(self.model_path / 'predictive_metadata.pkl')
                self.is_trained = metadata.get('is_trained', False)
                self.model_metrics = metadata.get('model_metrics', {})
            
            if self.is_trained:
                self.logger.info("Predictive models loaded successfully")
        except Exception as e:
            self.logger.error(f"Error loading predictive models: {e}")
            self.is_trained = False
