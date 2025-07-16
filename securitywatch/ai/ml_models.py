"""
SecurityWatch Pro - ML Model Manager
Centralized management of all AI/ML models and their lifecycle
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from pathlib import Path
import threading
import time

from ..core.database import SecurityDatabase
from .anomaly_detector import AnomalyDetector
from .threat_classifier import ThreatClassifier
from .behavioral_analyzer import BehavioralAnalyzer
from .predictive_engine import PredictiveEngine


class MLModelManager:
    """Centralized manager for all AI/ML models"""
    
    def __init__(self, database: SecurityDatabase, models_base_path: str = "models"):
        self.database = database
        self.models_path = Path(models_base_path)
        self.models_path.mkdir(exist_ok=True)
        self.logger = logging.getLogger('SecurityWatch.AI.MLModelManager')
        
        # Initialize AI components
        self.anomaly_detector = AnomalyDetector(database, str(self.models_path / "anomaly"))
        self.threat_classifier = ThreatClassifier(database, str(self.models_path / "classifier"))
        self.behavioral_analyzer = BehavioralAnalyzer(database)
        self.predictive_engine = PredictiveEngine(database, str(self.models_path / "predictive"))
        
        # Model management
        self.auto_retrain_enabled = True
        self.retrain_interval_days = 7
        self.last_training_check = datetime.now()
        
        # Performance tracking
        self.model_performance = {}
        self.training_history = []
        
        # Background training thread
        self.training_thread = None
        self.stop_training = False
        
        self.logger.info("ML Model Manager initialized")
    
    def train_all_models(self, force_retrain: bool = False) -> Dict:
        """Train all AI/ML models"""
        self.logger.info("Starting comprehensive AI model training...")
        
        training_results = {
            'started_at': datetime.now().isoformat(),
            'models_trained': {},
            'errors': [],
            'overall_success': True
        }
        
        # Train Anomaly Detector
        try:
            self.logger.info("Training anomaly detection models...")
            success = self.anomaly_detector.train_models()
            training_results['models_trained']['anomaly_detector'] = {
                'success': success,
                'trained_at': datetime.now().isoformat()
            }
            if not success:
                training_results['overall_success'] = False
        except Exception as e:
            error_msg = f"Anomaly detector training failed: {e}"
            self.logger.error(error_msg)
            training_results['errors'].append(error_msg)
            training_results['overall_success'] = False
        
        # Train Threat Classifier
        try:
            self.logger.info("Training threat classification models...")
            success = self.threat_classifier.train_classifiers()
            training_results['models_trained']['threat_classifier'] = {
                'success': success,
                'trained_at': datetime.now().isoformat()
            }
            if not success:
                training_results['overall_success'] = False
        except Exception as e:
            error_msg = f"Threat classifier training failed: {e}"
            self.logger.error(error_msg)
            training_results['errors'].append(error_msg)
            training_results['overall_success'] = False
        
        # Initialize Behavioral Analyzer (no explicit training needed)
        try:
            self.logger.info("Initializing behavioral analysis baselines...")
            self.behavioral_analyzer._initialize_baselines()
            training_results['models_trained']['behavioral_analyzer'] = {
                'success': True,
                'trained_at': datetime.now().isoformat()
            }
        except Exception as e:
            error_msg = f"Behavioral analyzer initialization failed: {e}"
            self.logger.error(error_msg)
            training_results['errors'].append(error_msg)
            training_results['overall_success'] = False
        
        # Train Predictive Engine
        try:
            self.logger.info("Training predictive models...")
            success = self.predictive_engine.train_prediction_models()
            training_results['models_trained']['predictive_engine'] = {
                'success': success,
                'trained_at': datetime.now().isoformat()
            }
            if not success:
                training_results['overall_success'] = False
        except Exception as e:
            error_msg = f"Predictive engine training failed: {e}"
            self.logger.error(error_msg)
            training_results['errors'].append(error_msg)
            training_results['overall_success'] = False
        
        training_results['completed_at'] = datetime.now().isoformat()
        training_results['duration_minutes'] = (
            datetime.fromisoformat(training_results['completed_at']) - 
            datetime.fromisoformat(training_results['started_at'])
        ).total_seconds() / 60
        
        # Update training history
        self.training_history.append(training_results)
        self.last_training_check = datetime.now()
        
        if training_results['overall_success']:
            self.logger.info("All AI models trained successfully")
        else:
            self.logger.warning("Some AI models failed to train. Check logs for details.")
        
        return training_results
    
    def analyze_events_comprehensive(self, events: List) -> Dict:
        """Run comprehensive AI analysis on security events"""
        if not events:
            return {}
        
        self.logger.info(f"Running comprehensive AI analysis on {len(events)} events...")
        
        analysis_results = {
            'analyzed_at': datetime.now().isoformat(),
            'event_count': len(events),
            'anomaly_detection': {},
            'threat_classification': {},
            'behavioral_analysis': {},
            'predictive_analysis': {}
        }
        
        # Anomaly Detection
        try:
            anomalies = self.anomaly_detector.detect_anomalies(events)
            analysis_results['anomaly_detection'] = {
                'anomalies_detected': len(anomalies),
                'anomalies': anomalies,
                'model_info': self.anomaly_detector.get_model_info()
            }
        except Exception as e:
            self.logger.error(f"Anomaly detection failed: {e}")
            analysis_results['anomaly_detection'] = {'error': str(e)}
        
        # Threat Classification
        try:
            classifications = self.threat_classifier.classify_threats(events)
            analysis_results['threat_classification'] = {
                'threats_classified': len(classifications),
                'classifications': classifications,
                'is_trained': self.threat_classifier.is_trained
            }
        except Exception as e:
            self.logger.error(f"Threat classification failed: {e}")
            analysis_results['threat_classification'] = {'error': str(e)}
        
        # Behavioral Analysis
        try:
            behavioral_anomalies = self.behavioral_analyzer.analyze_behavioral_anomalies(events)
            analysis_results['behavioral_analysis'] = {
                'behavioral_anomalies': len(behavioral_anomalies),
                'anomalies': behavioral_anomalies,
                'baseline_summary': self.behavioral_analyzer.get_baseline_summary()
            }
        except Exception as e:
            self.logger.error(f"Behavioral analysis failed: {e}")
            analysis_results['behavioral_analysis'] = {'error': str(e)}
        
        # Predictive Analysis
        try:
            predictions = self.predictive_engine.predict_threat_trends(24)
            analysis_results['predictive_analysis'] = predictions
        except Exception as e:
            self.logger.error(f"Predictive analysis failed: {e}")
            analysis_results['predictive_analysis'] = {'error': str(e)}
        
        # Generate comprehensive insights
        analysis_results['insights'] = self._generate_comprehensive_insights(analysis_results)
        
        return analysis_results
    
    def _generate_comprehensive_insights(self, analysis_results: Dict) -> Dict:
        """Generate comprehensive insights from all AI analyses"""
        insights = {
            'overall_threat_level': 'low',
            'confidence_score': 0.0,
            'key_findings': [],
            'recommendations': [],
            'risk_factors': []
        }
        
        # Analyze anomaly detection results
        anomalies = analysis_results.get('anomaly_detection', {}).get('anomalies', [])
        if anomalies:
            high_confidence_anomalies = [a for a in anomalies if a.get('confidence', 0) > 80]
            if high_confidence_anomalies:
                insights['key_findings'].append(f"🚨 {len(high_confidence_anomalies)} high-confidence anomalies detected")
                insights['risk_factors'].append("Anomalous behavior patterns detected")
        
        # Analyze threat classifications
        classifications = analysis_results.get('threat_classification', {}).get('classifications', [])
        if classifications:
            high_risk_threats = [c for c in classifications if c.get('risk_score', 0) > 70]
            if high_risk_threats:
                insights['key_findings'].append(f"⚠️ {len(high_risk_threats)} high-risk threats classified")
                insights['risk_factors'].append("High-risk threat patterns identified")
        
        # Analyze behavioral anomalies
        behavioral_anomalies = analysis_results.get('behavioral_analysis', {}).get('anomalies', [])
        if behavioral_anomalies:
            critical_behavioral = [a for a in behavioral_anomalies if a.get('severity') == 'critical']
            if critical_behavioral:
                insights['key_findings'].append(f"🔍 {len(critical_behavioral)} critical behavioral anomalies")
                insights['risk_factors'].append("Unusual behavioral patterns detected")
        
        # Analyze predictions
        predictions = analysis_results.get('predictive_analysis', {})
        if predictions and 'summary' in predictions:
            alerts = predictions['summary'].get('alerts', [])
            if alerts:
                insights['key_findings'].extend(alerts)
                insights['risk_factors'].append("Elevated future threat risk predicted")
        
        # Calculate overall threat level
        risk_score = 0
        if len(insights['risk_factors']) >= 3:
            risk_score = 80
            insights['overall_threat_level'] = 'critical'
        elif len(insights['risk_factors']) >= 2:
            risk_score = 60
            insights['overall_threat_level'] = 'high'
        elif len(insights['risk_factors']) >= 1:
            risk_score = 40
            insights['overall_threat_level'] = 'medium'
        else:
            risk_score = 20
            insights['overall_threat_level'] = 'low'
        
        insights['confidence_score'] = min(risk_score, 95)  # Cap at 95%
        
        # Generate recommendations
        if insights['overall_threat_level'] in ['critical', 'high']:
            insights['recommendations'].extend([
                "🚨 Immediate security review recommended",
                "📋 Activate incident response procedures",
                "🔍 Conduct detailed forensic analysis"
            ])
        elif insights['overall_threat_level'] == 'medium':
            insights['recommendations'].extend([
                "📊 Enhanced monitoring recommended",
                "🔧 Review security configurations",
                "👥 Brief security team on findings"
            ])
        else:
            insights['recommendations'].append("✅ Continue normal monitoring procedures")
        
        return insights
    
    def get_model_status(self) -> Dict:
        """Get comprehensive status of all AI models"""
        return {
            'anomaly_detector': {
                'is_trained': self.anomaly_detector.is_trained,
                'model_info': self.anomaly_detector.get_model_info()
            },
            'threat_classifier': {
                'is_trained': self.threat_classifier.is_trained,
                'model_path': str(self.threat_classifier.model_path)
            },
            'behavioral_analyzer': {
                'baseline_summary': self.behavioral_analyzer.get_baseline_summary()
            },
            'predictive_engine': {
                'is_trained': self.predictive_engine.is_trained,
                'model_metrics': self.predictive_engine.model_metrics
            },
            'manager_status': {
                'auto_retrain_enabled': self.auto_retrain_enabled,
                'last_training_check': self.last_training_check.isoformat(),
                'training_history_count': len(self.training_history)
            }
        }
    
    def start_auto_training(self):
        """Start automatic model retraining in background"""
        if self.training_thread and self.training_thread.is_alive():
            self.logger.warning("Auto-training already running")
            return
        
        self.stop_training = False
        self.training_thread = threading.Thread(target=self._auto_training_loop, daemon=True)
        self.training_thread.start()
        self.logger.info("Auto-training started")
    
    def stop_auto_training(self):
        """Stop automatic model retraining"""
        self.stop_training = True
        if self.training_thread and self.training_thread.is_alive():
            self.training_thread.join(timeout=10)
        self.logger.info("Auto-training stopped")
    
    def _auto_training_loop(self):
        """Background loop for automatic model retraining"""
        while not self.stop_training:
            try:
                # Check if retraining is needed
                time_since_last_training = datetime.now() - self.last_training_check
                
                if time_since_last_training.days >= self.retrain_interval_days:
                    self.logger.info("Auto-retraining models...")
                    self.train_all_models()
                
                # Sleep for 1 hour before next check
                for _ in range(3600):  # 1 hour = 3600 seconds
                    if self.stop_training:
                        break
                    time.sleep(1)
                    
            except Exception as e:
                self.logger.error(f"Error in auto-training loop: {e}")
                time.sleep(300)  # Wait 5 minutes before retrying
    
    def export_model_metrics(self) -> Dict:
        """Export comprehensive model performance metrics"""
        return {
            'export_timestamp': datetime.now().isoformat(),
            'model_status': self.get_model_status(),
            'training_history': self.training_history[-10:],  # Last 10 training sessions
            'performance_summary': {
                'total_training_sessions': len(self.training_history),
                'successful_trainings': len([t for t in self.training_history if t.get('overall_success')]),
                'last_successful_training': self._get_last_successful_training(),
                'models_operational': self._count_operational_models()
            }
        }
    
    def _get_last_successful_training(self) -> Optional[str]:
        """Get timestamp of last successful training"""
        for training in reversed(self.training_history):
            if training.get('overall_success'):
                return training.get('completed_at')
        return None
    
    def _count_operational_models(self) -> Dict:
        """Count how many models are operational"""
        return {
            'anomaly_detector': self.anomaly_detector.is_trained,
            'threat_classifier': self.threat_classifier.is_trained,
            'behavioral_analyzer': True,  # Always operational
            'predictive_engine': self.predictive_engine.is_trained,
            'total_operational': sum([
                self.anomaly_detector.is_trained,
                self.threat_classifier.is_trained,
                True,  # behavioral_analyzer
                self.predictive_engine.is_trained
            ])
        }
    
    def quick_analysis(self, events: List) -> Dict:
        """Run quick AI analysis for real-time monitoring"""
        if not events:
            return {}
        
        # Run only lightweight analyses for real-time use
        quick_results = {
            'analyzed_at': datetime.now().isoformat(),
            'event_count': len(events),
            'quick_anomalies': 0,
            'threat_level': 'low',
            'alerts': []
        }
        
        try:
            # Quick anomaly check
            if self.anomaly_detector.is_trained:
                anomalies = self.anomaly_detector.detect_anomalies(events[:50])  # Limit for speed
                quick_results['quick_anomalies'] = len(anomalies)
                
                if anomalies:
                    high_conf_anomalies = [a for a in anomalies if a.get('confidence', 0) > 80]
                    if high_conf_anomalies:
                        quick_results['threat_level'] = 'high'
                        quick_results['alerts'].append(f"🚨 {len(high_conf_anomalies)} high-confidence anomalies")
            
            # Quick behavioral check
            behavioral_anomalies = self.behavioral_analyzer.analyze_behavioral_anomalies(events[:30])
            if behavioral_anomalies:
                critical_behavioral = [a for a in behavioral_anomalies if a.get('severity') == 'critical']
                if critical_behavioral:
                    quick_results['threat_level'] = 'critical'
                    quick_results['alerts'].append(f"🔍 {len(critical_behavioral)} critical behavioral anomalies")
        
        except Exception as e:
            self.logger.error(f"Quick analysis failed: {e}")
            quick_results['error'] = str(e)
        
        return quick_results
