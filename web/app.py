#!/usr/bin/env python3
"""
Log Parser Web Interface
========================

Flask-based web application providing an intuitive interface for log analysis
with real-time processing, interactive visualizations, and comprehensive reporting.

Features:
- Drag-and-drop file upload with validation
- Real-time log parsing and analysis
- Interactive threat detection and anomaly identification
- Timeline visualization and statistical reporting
- Multi-format export (JSON, CSV, HTML)
- Session-based analysis management

Author: Samuel Tan
Version: 1.0
License: Educational Use Only
"""

import os
import sys
import json
import uuid
import time
import threading
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file, session
from werkzeug.utils import secure_filename

# Add the src directory to path to import log_parser
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))
from log_parser import LogParser

app = Flask(__name__)
app.secret_key = 'log-parser-web-interface-secret-key-2024'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['REPORTS_FOLDER'] = os.path.join(os.path.dirname(__file__), 'reports')

# Ensure required directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['REPORTS_FOLDER'], exist_ok=True)

# Global storage for analysis sessions
analysis_sessions = {}
session_cleanup_lock = threading.Lock()

# Allowed file extensions for log files
ALLOWED_EXTENSIONS = {
    'log', 'txt', 'access', 'error', 'out', 'syslog', 
    'gz', 'zip', 'json', 'csv', 'tsv'
}

def allowed_file(filename):
    """Check if uploaded file has allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_session_id():
    """Get or create session ID for current user."""
    if 'session_id' not in session:
        session['session_id'] = str(uuid.uuid4())
    return session['session_id']

def cleanup_old_sessions():
    """Clean up old analysis sessions and files."""
    with session_cleanup_lock:
        current_time = time.time()
        sessions_to_remove = []
        
        for session_id, session_data in analysis_sessions.items():
            # Remove sessions older than 2 hours
            if current_time - session_data.get('created_at', 0) > 7200:
                sessions_to_remove.append(session_id)
        
        for session_id in sessions_to_remove:
            session_data = analysis_sessions.pop(session_id, {})
            
            # Clean up uploaded files
            if 'uploaded_files' in session_data:
                for file_path in session_data['uploaded_files']:
                    try:
                        if os.path.exists(file_path):
                            os.remove(file_path)
                    except:
                        pass
            
            # Clean up database file
            if 'db_path' in session_data:
                try:
                    if os.path.exists(session_data['db_path']):
                        os.remove(session_data['db_path'])
                except:
                    pass

def background_cleanup():
    """Background thread for periodic cleanup."""
    while True:
        time.sleep(1800)  # Run every 30 minutes
        cleanup_old_sessions()

# Start background cleanup thread
cleanup_thread = threading.Thread(target=background_cleanup, daemon=True)
cleanup_thread.start()

@app.route('/')
def index():
    """Main web interface page."""
    return render_template('index.html')

@app.route('/api/health')
def health_check():
    """API health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'tool': 'Log Parser',
        'version': '1.0',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/upload', methods=['POST'])
def upload_files():
    """
    Handle file upload for log analysis.
    
    Returns:
        JSON response with upload status and file information
    """
    session_id = get_session_id()
    
    if 'files' not in request.files:
        return jsonify({'error': 'No files provided'}), 400
    
    files = request.files.getlist('files')
    
    if not files or all(file.filename == '' for file in files):
        return jsonify({'error': 'No files selected'}), 400
    
    uploaded_files = []
    total_size = 0
    
    # Initialize session data
    if session_id not in analysis_sessions:
        analysis_sessions[session_id] = {
            'created_at': time.time(),
            'uploaded_files': [],
            'db_path': os.path.join(app.config['UPLOAD_FOLDER'], f'session_{session_id}.db'),
            'log_parser': LogParser(os.path.join(app.config['UPLOAD_FOLDER'], f'session_{session_id}.db'))
        }
    
    try:
        for file in files:
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                
                # Add timestamp to avoid filename conflicts
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"{timestamp}_{filename}"
                
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                
                file_size = os.path.getsize(file_path)
                total_size += file_size
                
                uploaded_files.append({
                    'filename': file.filename,  # Original filename
                    'saved_filename': filename,
                    'file_path': file_path,
                    'size': file_size,
                    'size_mb': round(file_size / (1024 * 1024), 2)
                })
                
                analysis_sessions[session_id]['uploaded_files'].append(file_path)
            
            else:
                return jsonify({
                    'error': f'File type not allowed: {file.filename}. Allowed types: {", ".join(ALLOWED_EXTENSIONS)}'
                }), 400
        
        # Check total size limit (100MB)
        if total_size > app.config['MAX_CONTENT_LENGTH']:
            # Clean up uploaded files
            for file_info in uploaded_files:
                try:
                    os.remove(file_info['file_path'])
                except:
                    pass
            
            return jsonify({
                'error': f'Total file size exceeds limit (100MB). Total: {round(total_size / (1024 * 1024), 2)}MB'
            }), 400
        
        return jsonify({
            'success': True,
            'files_uploaded': len(uploaded_files),
            'total_size_mb': round(total_size / (1024 * 1024), 2),
            'files': uploaded_files
        })
    
    except Exception as e:
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500

@app.route('/api/analyze', methods=['POST'])
def analyze_logs():
    """
    Perform log analysis on uploaded files.
    
    Returns:
        JSON response with analysis results
    """
    session_id = get_session_id()
    
    if session_id not in analysis_sessions:
        return jsonify({'error': 'No active session found. Please upload files first.'}), 400
    
    data = request.get_json() or {}
    log_format = data.get('format', 'auto')
    encoding = data.get('encoding', 'utf-8')
    
    session_data = analysis_sessions[session_id]
    log_parser = session_data['log_parser']
    
    try:
        analysis_results = {
            'session_id': session_id,
            'analysis_timestamp': datetime.now().isoformat(),
            'files_analyzed': [],
            'total_entries': 0,
            'total_parsing_time': 0,
            'threats_summary': {},
            'errors': []
        }
        
        # Analyze each uploaded file
        for file_path in session_data['uploaded_files']:
            if not os.path.exists(file_path):
                analysis_results['errors'].append(f'File not found: {file_path}')
                continue
            
            result = log_parser.parse_log_file(file_path, log_format, encoding)
            
            if 'error' in result:
                analysis_results['errors'].append(f'Error in {os.path.basename(file_path)}: {result["error"]}')
                continue
            
            file_analysis = {
                'filename': os.path.basename(file_path),
                'entries_parsed': result['entries_parsed'],
                'entries_failed': result['entries_failed'],
                'parsing_time': result['parsing_time'],
                'threats_found': dict(result['threats_found']),
                'format_detected': log_format
            }
            
            analysis_results['files_analyzed'].append(file_analysis)
            analysis_results['total_entries'] += result['entries_parsed']
            analysis_results['total_parsing_time'] += result['parsing_time']
            
            # Aggregate threat summary
            for threat_type, threats in result['threats_found'].items():
                if threat_type not in analysis_results['threats_summary']:
                    analysis_results['threats_summary'][threat_type] = 0
                analysis_results['threats_summary'][threat_type] += len(threats)
        
        # Get current analysis state from log parser
        current_results = log_parser.analysis_results
        analysis_results.update({
            'top_ips': dict(current_results['top_ips'].most_common(10)),
            'status_codes': dict(current_results['status_codes']),
            'top_user_agents': dict(current_results['top_user_agents'].most_common(5))
        })
        
        # Store results in session
        session_data['last_analysis'] = analysis_results
        
        return jsonify(analysis_results)
    
    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

@app.route('/api/detect-anomalies', methods=['POST'])
def detect_anomalies():
    """
    Perform anomaly detection on analyzed logs.
    
    Returns:
        JSON response with detected anomalies
    """
    session_id = get_session_id()
    
    if session_id not in analysis_sessions:
        return jsonify({'error': 'No active session found. Please analyze logs first.'}), 400
    
    data = request.get_json() or {}
    analysis_type = data.get('type', 'statistical')
    
    session_data = analysis_sessions[session_id]
    log_parser = session_data['log_parser']
    
    try:
        anomalies = log_parser.detect_anomalies(analysis_type)
        
        # Categorize anomalies by severity
        anomaly_summary = {
            'total_anomalies': len(anomalies),
            'high_severity': len([a for a in anomalies if a['details'].get('severity') == 'HIGH']),
            'medium_severity': len([a for a in anomalies if a['details'].get('severity') == 'MEDIUM']),
            'low_severity': len([a for a in anomalies if a['details'].get('severity') == 'LOW']),
            'analysis_type': analysis_type,
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify({
            'success': True,
            'summary': anomaly_summary,
            'anomalies': anomalies
        })
    
    except Exception as e:
        return jsonify({'error': f'Anomaly detection failed: {str(e)}'}), 500

@app.route('/api/search', methods=['POST'])
def search_logs():
    """
    Search through analyzed logs.
    
    Returns:
        JSON response with search results
    """
    session_id = get_session_id()
    
    if session_id not in analysis_sessions:
        return jsonify({'error': 'No active session found. Please analyze logs first.'}), 400
    
    data = request.get_json() or {}
    query = data.get('query', '')
    search_type = data.get('type', 'text')
    limit = data.get('limit', 100)
    
    if not query:
        return jsonify({'error': 'Search query is required'}), 400
    
    session_data = analysis_sessions[session_id]
    log_parser = session_data['log_parser']
    
    try:
        results = log_parser.search_logs(query, search_type)
        
        # Limit results
        if len(results) > limit:
            results = results[:limit]
            limited = True
        else:
            limited = False
        
        return jsonify({
            'success': True,
            'query': query,
            'search_type': search_type,
            'total_results': len(results),
            'limited': limited,
            'limit': limit,
            'results': results
        })
    
    except Exception as e:
        return jsonify({'error': f'Search failed: {str(e)}'}), 500

@app.route('/api/timeline', methods=['GET'])
def get_timeline():
    """
    Get timeline analysis of logs.
    
    Returns:
        JSON response with timeline data
    """
    session_id = get_session_id()
    
    if session_id not in analysis_sessions:
        return jsonify({'error': 'No active session found. Please analyze logs first.'}), 400
    
    session_data = analysis_sessions[session_id]
    log_parser = session_data['log_parser']
    
    try:
        timeline = log_parser.generate_timeline_analysis()
        
        return jsonify({
            'success': True,
            'timeline': timeline,
            'generated_at': datetime.now().isoformat()
        })
    
    except Exception as e:
        return jsonify({'error': f'Timeline generation failed: {str(e)}'}), 500

@app.route('/api/report', methods=['POST'])
def generate_report():
    """
    Generate comprehensive analysis report.
    
    Returns:
        JSON response with report generation status
    """
    session_id = get_session_id()
    
    if session_id not in analysis_sessions:
        return jsonify({'error': 'No active session found. Please analyze logs first.'}), 400
    
    data = request.get_json() or {}
    format_type = data.get('format', 'json')
    
    if format_type not in ['json', 'csv', 'html']:
        return jsonify({'error': 'Invalid format. Use: json, csv, or html'}), 400
    
    session_data = analysis_sessions[session_id]
    log_parser = session_data['log_parser']
    
    try:
        # Generate filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'log_analysis_report_{timestamp}.{format_type}'
        report_path = os.path.join(app.config['REPORTS_FOLDER'], filename)
        
        # Generate report
        log_parser.generate_report(format_type, report_path)
        
        # Store report info in session
        if 'reports' not in session_data:
            session_data['reports'] = []
        
        report_info = {
            'filename': filename,
            'format': format_type,
            'path': report_path,
            'generated_at': datetime.now().isoformat(),
            'size': os.path.getsize(report_path)
        }
        
        session_data['reports'].append(report_info)
        
        return jsonify({
            'success': True,
            'report': report_info,
            'download_url': f'/api/download/{session_id}/{filename}'
        })
    
    except Exception as e:
        return jsonify({'error': f'Report generation failed: {str(e)}'}), 500

@app.route('/api/download/<session_id>/<filename>')
def download_report(session_id, filename):
    """
    Download generated reports.
    
    Args:
        session_id: User session ID
        filename: Report filename
        
    Returns:
        File download response
    """
    if session_id not in analysis_sessions:
        return jsonify({'error': 'Session not found'}), 404
    
    session_data = analysis_sessions[session_id]
    
    # Verify file belongs to session
    report_found = False
    report_path = None
    
    if 'reports' in session_data:
        for report in session_data['reports']:
            if report['filename'] == filename:
                report_path = report['path']
                report_found = True
                break
    
    if not report_found or not report_path or not os.path.exists(report_path):
        return jsonify({'error': 'Report not found'}), 404
    
    try:
        return send_file(
            report_path,
            as_attachment=True,
            download_name=filename,
            mimetype='application/octet-stream'
        )
    except Exception as e:
        return jsonify({'error': f'Download failed: {str(e)}'}), 500

@app.route('/api/session-info')
def get_session_info():
    """
    Get current session information.
    
    Returns:
        JSON response with session details
    """
    session_id = get_session_id()
    
    if session_id not in analysis_sessions:
        return jsonify({
            'session_id': session_id,
            'has_data': False,
            'created_at': None
        })
    
    session_data = analysis_sessions[session_id]
    
    info = {
        'session_id': session_id,
        'has_data': True,
        'created_at': datetime.fromtimestamp(session_data['created_at']).isoformat(),
        'files_uploaded': len(session_data.get('uploaded_files', [])),
        'total_entries': session_data['log_parser'].analysis_results.get('total_entries', 0),
        'reports_generated': len(session_data.get('reports', []))
    }
    
    if 'last_analysis' in session_data:
        info['last_analysis'] = session_data['last_analysis']['analysis_timestamp']
    
    return jsonify(info)

@app.route('/api/clear-session', methods=['POST'])
def clear_session():
    """
    Clear current session data.
    
    Returns:
        JSON response with clear status
    """
    session_id = get_session_id()
    
    if session_id in analysis_sessions:
        session_data = analysis_sessions.pop(session_id)
        
        # Clean up files
        for file_path in session_data.get('uploaded_files', []):
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
            except:
                pass
        
        # Clean up database
        if 'db_path' in session_data:
            try:
                if os.path.exists(session_data['db_path']):
                    os.remove(session_data['db_path'])
            except:
                pass
        
        # Clean up reports
        for report in session_data.get('reports', []):
            try:
                if os.path.exists(report['path']):
                    os.remove(report['path'])
            except:
                pass
    
    # Clear Flask session
    session.clear()
    
    return jsonify({'success': True, 'message': 'Session cleared successfully'})

@app.errorhandler(413)
def file_too_large(error):
    """Handle file too large error."""
    return jsonify({'error': 'File too large. Maximum size is 100MB.'}), 413

@app.errorhandler(500)
def internal_error(error):
    """Handle internal server errors."""
    return jsonify({'error': 'Internal server error occurred.'}), 500

if __name__ == '__main__':
    print("="*60)
    print("Log Parser Web Interface")
    print("="*60)
    print("Starting Flask development server...")
    print("Access the web interface at: http://localhost:5000")
    print("API documentation available at: http://localhost:5000/api/health")
    print("")
    print("Features available:")
    print("  - Drag-and-drop file upload")
    print("  - Real-time log analysis")
    print("  - Threat detection and anomaly identification")
    print("  - Timeline analysis and reporting")
    print("  - Multi-format export (JSON, CSV, HTML)")
    print("")
    print("Educational Use Only - Ensure proper authorization")
    print("="*60)
    
    # Create upload and reports directories
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['REPORTS_FOLDER'], exist_ok=True)
    
    # Run Flask development server
    app.run(
        host='127.0.0.1',
        port=5000,
        debug=True,
        threaded=True
    )