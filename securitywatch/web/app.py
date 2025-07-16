"""
SecurityWatch Pro - Flask Web Application
"""

import os
import json
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
from flask_socketio import SocketIO, emit
import threading
import time

from ..core.monitor import SecurityWatchMonitor
from ..core.database import SecurityDatabase
from ..core.analyzer import ThreatAnalyzer
from ..core.reports import ReportGenerator
from ..config.settings import SecurityWatchConfig


def create_app():
    """Create and configure Flask application"""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'securitywatch-pro-web-interface-2025'
    
    # Initialize SocketIO for real-time updates
    socketio = SocketIO(app, cors_allowed_origins="*")
    
    # Initialize SecurityWatch components
    config = SecurityWatchConfig()
    monitor = SecurityWatchMonitor(config)
    database = SecurityDatabase()
    analyzer = ThreatAnalyzer(database)
    report_generator = ReportGenerator(database)
    
    # Store components in app context
    app.config['MONITOR'] = monitor
    app.config['DATABASE'] = database
    app.config['ANALYZER'] = analyzer
    app.config['REPORT_GENERATOR'] = report_generator
    app.config['CONFIG'] = config
    app.config['SOCKETIO'] = socketio
    
    @app.route('/')
    def dashboard():
        """Main dashboard page"""
        # Get recent statistics
        stats = database.get_statistics()
        recent_events = database.get_recent_events(24)
        analysis = analyzer.analyze_events(recent_events)
        
        return render_template('dashboard.html',
                             stats=stats,
                             analysis=analysis,
                             recent_events=recent_events[:10])
    
    @app.route('/api/stats')
    def api_stats():
        """API endpoint for dashboard statistics"""
        stats = database.get_statistics()
        recent_events = database.get_recent_events(1)  # Last hour
        analysis = analyzer.analyze_events(recent_events)
        
        return jsonify({
            'total_events': stats.get('total_events', 0),
            'recent_events': len(recent_events),
            'threat_score': analysis.get('threat_score', 0),
            'brute_force_attacks': len(analysis.get('brute_force_attempts', [])),
            'severity_breakdown': dict(analysis.get('severity_breakdown', {})),
            'top_ips': analysis.get('top_source_ips', {})
        })
    
    @app.route('/api/events')
    def api_events():
        """API endpoint for recent events"""
        hours = request.args.get('hours', 24, type=int)
        limit = request.args.get('limit', 50, type=int)
        
        events = database.get_recent_events(hours)[:limit]
        
        events_data = []
        for event in events:
            events_data.append({
                'timestamp': event.timestamp.isoformat(),
                'event_type': event.event_type,
                'source_ip': event.source_ip,
                'username': event.username,
                'severity': event.severity,
                'details': event.details[:100] + '...' if len(event.details) > 100 else event.details
            })
        
        return jsonify(events_data)
    
    @app.route('/api/analysis/<ip>')
    def api_ip_analysis(ip):
        """API endpoint for IP analysis"""
        hours = request.args.get('hours', 24, type=int)
        analysis = analyzer.get_ip_analysis(ip, hours)
        return jsonify(analysis)
    
    @app.route('/reports')
    def reports():
        """Reports page"""
        return render_template('reports.html')
    
    @app.route('/api/generate-report')
    def api_generate_report():
        """Generate and return report"""
        report_type = request.args.get('type', 'json')
        hours = request.args.get('hours', 24, type=int)
        
        if report_type == 'json':
            report_data = report_generator.generate_json_report(hours)
            return jsonify(report_data)
        elif report_type == 'html':
            html_content = report_generator.generate_html_report(hours)
            return html_content
        else:
            return jsonify({'error': 'Invalid report type'}), 400
    
    @app.route('/config')
    def configuration():
        """Configuration page"""
        config_summary = config.get_config_summary()
        return render_template('config.html', config=config_summary)
    
    @app.route('/api/config', methods=['GET', 'POST'])
    def api_config():
        """Configuration API endpoint"""
        if request.method == 'GET':
            return jsonify(config.get_config_summary())
        
        elif request.method == 'POST':
            data = request.get_json()
            
            # Update email configuration
            if 'email' in data:
                email_config = data['email']
                config.update_email_config(
                    email_config.get('smtp_server', ''),
                    email_config.get('smtp_port', 587),
                    email_config.get('username', ''),
                    email_config.get('password', ''),
                    email_config.get('from_email', ''),
                    email_config.get('to_emails', [])
                )
            
            flash('Configuration updated successfully!', 'success')
            return jsonify({'status': 'success'})
    
    @app.route('/monitoring')
    def monitoring():
        """Monitoring control page"""
        status = monitor.get_status()
        return render_template('monitoring.html', status=status)
    
    @app.route('/api/monitoring/<action>')
    def api_monitoring(action):
        """Monitoring control API"""
        if action == 'start':
            monitor.start_monitoring()
            return jsonify({'status': 'started'})
        elif action == 'stop':
            monitor.stop_monitoring()
            return jsonify({'status': 'stopped'})
        elif action == 'status':
            status = monitor.get_status()
            return jsonify(status)
        elif action == 'scan':
            result = monitor.run_manual_scan()
            return jsonify(result)
        else:
            return jsonify({'error': 'Invalid action'}), 400
    
    # Real-time WebSocket events
    @socketio.on('connect')
    def handle_connect():
        """Handle client connection"""
        emit('status', {'message': 'Connected to SecurityWatch Pro'})
    
    @socketio.on('request_stats')
    def handle_stats_request():
        """Handle real-time stats request"""
        stats = database.get_statistics()
        recent_events = database.get_recent_events(1)
        analysis = analyzer.analyze_events(recent_events)
        
        emit('stats_update', {
            'total_events': stats.get('total_events', 0),
            'recent_events': len(recent_events),
            'threat_score': analysis.get('threat_score', 0),
            'timestamp': datetime.now().isoformat()
        })
    
    # Background task for real-time updates
    def background_updates():
        """Send periodic updates to connected clients"""
        while True:
            time.sleep(5)  # Update every 5 seconds
            
            stats = database.get_statistics()
            recent_events = database.get_recent_events(1)
            analysis = analyzer.analyze_events(recent_events)
            
            socketio.emit('live_update', {
                'total_events': stats.get('total_events', 0),
                'recent_events': len(recent_events),
                'threat_score': analysis.get('threat_score', 0),
                'severity_breakdown': dict(analysis.get('severity_breakdown', {})),
                'timestamp': datetime.now().isoformat()
            })
    
    # Start background updates thread
    update_thread = threading.Thread(target=background_updates, daemon=True)
    update_thread.start()
    
    return app, socketio


def run_web_server(host='127.0.0.1', port=5000, debug=False):
    """Run the web server"""
    app, socketio = create_app()
    print(f"🌐 Starting SecurityWatch Pro Web Dashboard...")
    print(f"🔗 Access at: http://{host}:{port}")
    socketio.run(app, host=host, port=port, debug=debug)
