#!/usr/bin/env python3
"""
Log Parser - Intelligent Log Analysis Tool
==========================================

A comprehensive log analysis tool with pattern recognition, anomaly detection,
and statistical reporting capabilities for cybersecurity and system administration.

Features:
- Multi-format log parsing (syslog, Apache, nginx, Windows Event Log, custom formats)
- Real-time pattern recognition and regex-based filtering
- Anomaly detection using statistical analysis
- Time-series analysis and trend identification
- Threat intelligence correlation
- Interactive web interface and CLI
- Comprehensive reporting (JSON, CSV, HTML)

Author: Samuel Tan
Version: 1.0
License: Educational Use Only
"""

import argparse
import json
import csv
import re
import sqlite3
import hashlib
import gzip
import zipfile
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, Counter
import statistics
import math
from typing import Dict, List, Tuple, Optional, Any, Set
import urllib.parse

class LogParser:
    """
    Advanced log analysis engine with pattern recognition and anomaly detection.
    """
    
    def __init__(self, db_path: str = "log_analysis.db"):
        """Initialize the Log Parser with database connection."""
        self.db_path = db_path
        self.init_database()
        
        # Predefined log patterns for common formats
        self.log_patterns = {
            'apache_common': r'^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3}) (\S+)',
            'apache_combined': r'^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3}) (\S+) "([^"]*)" "([^"]*)"',
            'nginx_access': r'^(\S+) - (\S+) \[([^\]]+)\] "([^"]*)" (\d{3}) (\d+) "([^"]*)" "([^"]*)"',
            'syslog': r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) (\S+) ([^:]+): (.*)',
            'windows_event': r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\w+)\s+(\d+)\s+(.*)',
            'ssh_auth': r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) (\S+) sshd\[(\d+)\]: (.*)',
            'firewall_pf': r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) (\S+) kernel: (.+) on (\S+): (.+)',
            'custom': r'^(.*)$'  # Fallback pattern
        }
        
        # Threat indicators for security analysis
        self.threat_indicators = {
            'sql_injection': [
                r"(\bunion\b.*\bselect\b)|(\bselect\b.*\bunion\b)",
                r"'.*\bor\b.*'.*=.*'",
                r"'\s*;\s*(drop|delete|insert|update)",
                r"\b(exec|execute)\s*\(",
                r"(\bxp_|\bsp_)"
            ],
            'xss_attempts': [
                r"<script[^>]*>.*</script>",
                r"javascript:",
                r"on(load|error|click|mouseover)\s*=",
                r"<iframe[^>]*>",
                r"eval\s*\("
            ],
            'brute_force': [
                r"failed\s+login",
                r"authentication\s+failure",
                r"invalid\s+user",
                r"password\s+incorrect",
                r"login\s+incorrect"
            ],
            'directory_traversal': [
                r"\.\.\/",
                r"\.\.\\",
                r"%2e%2e%2f",
                r"%2e%2e%5c"
            ],
            'command_injection': [
                r";\s*(ls|cat|wget|curl|nc|netcat)",
                r"\|\s*(ls|cat|wget|curl|nc|netcat)",
                r"&&\s*(ls|cat|wget|curl|nc|netcat)",
                r"`.*`",
                r"\$\(.*\)"
            ]
        }
        
        # Status codes and their meanings
        self.http_status_codes = {
            '200': 'OK', '201': 'Created', '204': 'No Content',
            '301': 'Moved Permanently', '302': 'Found', '304': 'Not Modified',
            '400': 'Bad Request', '401': 'Unauthorized', '403': 'Forbidden',
            '404': 'Not Found', '405': 'Method Not Allowed', '429': 'Too Many Requests',
            '500': 'Internal Server Error', '502': 'Bad Gateway', '503': 'Service Unavailable'
        }
        
        # Analysis results storage
        self.analysis_results = {
            'total_entries': 0,
            'patterns_found': defaultdict(int),
            'threats_detected': defaultdict(list),
            'anomalies': [],
            'timeline_analysis': {},
            'top_ips': Counter(),
            'top_user_agents': Counter(),
            'status_codes': Counter(),
            'error_trends': [],
            'performance_metrics': {}
        }

    def init_database(self):
        """Initialize SQLite database for log analysis storage."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables for log entries and analysis results
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS log_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source_file TEXT,
                log_type TEXT,
                ip_address TEXT,
                method TEXT,
                url TEXT,
                status_code TEXT,
                size INTEGER,
                user_agent TEXT,
                raw_entry TEXT,
                threats TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analysis_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE,
                files_analyzed INTEGER,
                total_entries INTEGER,
                threats_found INTEGER,
                anomalies_found INTEGER,
                analysis_time REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_type TEXT,
                pattern_name TEXT,
                pattern_regex TEXT,
                severity TEXT,
                description TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        
        # Insert default threat patterns
        self._insert_default_patterns()

    def _insert_default_patterns(self):
        """Insert default threat detection patterns into database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check if patterns already exist
        cursor.execute("SELECT COUNT(*) FROM threat_patterns")
        if cursor.fetchone()[0] > 0:
            conn.close()
            return
        
        # Insert threat patterns
        patterns_to_insert = [
            ('sql_injection', 'Union-based SQLi', r"(\bunion\b.*\bselect\b)|(\bselect\b.*\bunion\b)", 'HIGH', 'SQL injection using UNION statements'),
            ('sql_injection', 'Boolean-based SQLi', r"'.*\bor\b.*'.*=.*'", 'HIGH', 'Boolean-based SQL injection'),
            ('xss_attempts', 'Script injection', r"<script[^>]*>.*</script>", 'MEDIUM', 'JavaScript injection attempt'),
            ('brute_force', 'Failed login', r"failed\s+login", 'MEDIUM', 'Failed authentication attempt'),
            ('directory_traversal', 'Path traversal', r"\.\.\/", 'MEDIUM', 'Directory traversal attempt'),
            ('command_injection', 'Command execution', r";\s*(ls|cat|wget|curl)", 'HIGH', 'Command injection attempt')
        ]
        
        cursor.executemany(
            "INSERT INTO threat_patterns (pattern_type, pattern_name, pattern_regex, severity, description) VALUES (?, ?, ?, ?, ?)",
            patterns_to_insert
        )
        
        conn.commit()
        conn.close()

    def parse_log_file(self, file_path: str, log_format: str = 'auto', encoding: str = 'utf-8') -> Dict[str, Any]:
        """
        Parse a log file and extract structured information.
        
        Args:
            file_path: Path to the log file
            log_format: Log format type ('auto', 'apache_common', 'nginx_access', etc.)
            encoding: File encoding
            
        Returns:
            Dictionary containing parsing results
        """
        print(f"[+] Parsing log file: {file_path}")
        
        if not os.path.exists(file_path):
            return {'error': f'File not found: {file_path}'}
        
        results = {
            'file_path': file_path,
            'entries_parsed': 0,
            'entries_failed': 0,
            'patterns_detected': defaultdict(int),
            'threats_found': defaultdict(list),
            'parsing_time': 0
        }
        
        start_time = time.time()
        
        try:
            # Handle compressed files
            if file_path.endswith(('.gz', '.zip')):
                content = self._read_compressed_file(file_path)
            else:
                with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                    content = f.read()
            
            lines = content.strip().split('\n')
            
            # Auto-detect log format if needed
            if log_format == 'auto':
                log_format = self._detect_log_format(lines[:10])
                print(f"[+] Auto-detected log format: {log_format}")
            
            pattern = self.log_patterns.get(log_format, self.log_patterns['custom'])
            
            # Parse each line
            for line_num, line in enumerate(lines, 1):
                if not line.strip():
                    continue
                    
                parsed_entry = self._parse_log_line(line, pattern, log_format)
                
                if parsed_entry:
                    # Store in database
                    self._store_log_entry(parsed_entry, file_path, log_format)
                    
                    # Check for threats
                    threats = self._detect_threats(line)
                    if threats:
                        parsed_entry['threats'] = threats
                        for threat_type, matches in threats.items():
                            results['threats_found'][threat_type].extend(matches)
                    
                    results['entries_parsed'] += 1
                    
                    # Update analysis results
                    self._update_analysis_results(parsed_entry)
                    
                else:
                    results['entries_failed'] += 1
                    if results['entries_failed'] <= 5:  # Log first few failures
                        print(f"[-] Failed to parse line {line_num}: {line[:100]}...")
            
            results['parsing_time'] = time.time() - start_time
            print(f"[+] Parsing completed: {results['entries_parsed']} entries in {results['parsing_time']:.2f}s")
            
        except Exception as e:
            results['error'] = f"Error parsing file: {str(e)}"
            print(f"[-] Error: {str(e)}")
        
        return results

    def _read_compressed_file(self, file_path: str) -> str:
        """Read compressed log files (gzip, zip)."""
        if file_path.endswith('.gz'):
            with gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
                return f.read()
        elif file_path.endswith('.zip'):
            with zipfile.ZipFile(file_path, 'r') as z:
                # Read first file in zip
                filename = z.namelist()[0]
                with z.open(filename) as f:
                    return f.read().decode('utf-8', errors='ignore')
        return ""

    def _detect_log_format(self, sample_lines: List[str]) -> str:
        """Auto-detect log format based on sample lines."""
        format_scores = defaultdict(int)
        
        for line in sample_lines:
            if not line.strip():
                continue
                
            # Test each pattern
            for format_name, pattern in self.log_patterns.items():
                if format_name == 'custom':
                    continue
                    
                if re.search(pattern, line):
                    format_scores[format_name] += 1
        
        if format_scores:
            return max(format_scores.items(), key=lambda x: x[1])[0]
        
        return 'custom'

    def _parse_log_line(self, line: str, pattern: str, log_format: str) -> Optional[Dict[str, Any]]:
        """Parse a single log line based on the specified pattern."""
        match = re.search(pattern, line)
        
        if not match:
            return None
        
        groups = match.groups()
        parsed = {'raw_entry': line}
        
        # Parse based on format
        if log_format in ['apache_common', 'apache_combined']:
            parsed.update({
                'ip_address': groups[0],
                'timestamp': groups[1],
                'request': groups[2] if len(groups) > 2 else '',
                'status_code': groups[3] if len(groups) > 3 else '',
                'size': self._safe_int(groups[4]) if len(groups) > 4 else 0
            })
            
            # Parse request method and URL
            if 'request' in parsed and parsed['request']:
                request_parts = parsed['request'].split(' ')
                if len(request_parts) >= 2:
                    parsed['method'] = request_parts[0]
                    parsed['url'] = request_parts[1]
            
            # Additional fields for combined format
            if log_format == 'apache_combined' and len(groups) > 6:
                parsed.update({
                    'referer': groups[5] if groups[5] != '-' else '',
                    'user_agent': groups[6] if groups[6] != '-' else ''
                })
                
        elif log_format == 'nginx_access':
            parsed.update({
                'ip_address': groups[0],
                'user': groups[1] if groups[1] != '-' else '',
                'timestamp': groups[2],
                'request': groups[3],
                'status_code': groups[4],
                'size': self._safe_int(groups[5]),
                'referer': groups[6] if len(groups) > 6 and groups[6] != '-' else '',
                'user_agent': groups[7] if len(groups) > 7 and groups[7] != '-' else ''
            })
            
        elif log_format == 'syslog':
            parsed.update({
                'timestamp': groups[0],
                'hostname': groups[1],
                'process': groups[2],
                'message': groups[3]
            })
            
        elif log_format == 'windows_event':
            parsed.update({
                'timestamp': groups[0],
                'level': groups[1],
                'event_id': groups[2],
                'message': groups[3]
            })
            
        elif log_format == 'ssh_auth':
            parsed.update({
                'timestamp': groups[0],
                'hostname': groups[1],
                'pid': groups[2],
                'message': groups[3]
            })
            
        else:  # custom format
            parsed['content'] = groups[0] if groups else line
        
        # Standardize timestamp
        parsed['parsed_timestamp'] = self._parse_timestamp(parsed.get('timestamp', ''))
        
        return parsed

    def _safe_int(self, value: str) -> int:
        """Safely convert string to integer."""
        try:
            return int(value) if value and value != '-' else 0
        except ValueError:
            return 0

    def _parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse timestamp string into datetime object."""
        if not timestamp_str:
            return None
            
        # Common timestamp formats
        formats = [
            '%d/%b/%Y:%H:%M:%S %z',  # Apache format
            '%d/%b/%Y:%H:%M:%S',     # Apache without timezone
            '%Y-%m-%d %H:%M:%S',     # Standard format
            '%b %d %H:%M:%S',        # Syslog format
            '%Y-%m-%dT%H:%M:%S',     # ISO format
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue
        
        return None

    def _detect_threats(self, log_line: str) -> Dict[str, List[str]]:
        """Detect security threats in log line."""
        threats = defaultdict(list)
        
        for threat_type, patterns in self.threat_indicators.items():
            for pattern in patterns:
                matches = re.findall(pattern, log_line, re.IGNORECASE)
                if matches:
                    threats[threat_type].extend([str(m) for m in matches])
        
        return dict(threats)

    def _store_log_entry(self, entry: Dict[str, Any], source_file: str, log_type: str):
        """Store parsed log entry in database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO log_entries 
            (timestamp, source_file, log_type, ip_address, method, url, status_code, 
             size, user_agent, raw_entry, threats)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            entry.get('timestamp', ''),
            source_file,
            log_type,
            entry.get('ip_address', ''),
            entry.get('method', ''),
            entry.get('url', ''),
            entry.get('status_code', ''),
            entry.get('size', 0),
            entry.get('user_agent', ''),
            entry.get('raw_entry', ''),
            json.dumps(entry.get('threats', {}))
        ))
        
        conn.commit()
        conn.close()

    def _update_analysis_results(self, entry: Dict[str, Any]):
        """Update global analysis results with new entry."""
        self.analysis_results['total_entries'] += 1
        
        # Update IP statistics
        if 'ip_address' in entry and entry['ip_address']:
            self.analysis_results['top_ips'][entry['ip_address']] += 1
        
        # Update status code statistics
        if 'status_code' in entry and entry['status_code']:
            self.analysis_results['status_codes'][entry['status_code']] += 1
        
        # Update user agent statistics
        if 'user_agent' in entry and entry['user_agent']:
            self.analysis_results['top_user_agents'][entry['user_agent']] += 1

    def detect_anomalies(self, analysis_type: str = 'statistical') -> List[Dict[str, Any]]:
        """
        Detect anomalies in log data using various methods.
        
        Args:
            analysis_type: Type of anomaly detection ('statistical', 'temporal', 'behavioral')
            
        Returns:
            List of detected anomalies
        """
        print(f"[+] Running anomaly detection: {analysis_type}")
        
        anomalies = []
        
        if analysis_type in ['statistical', 'all']:
            anomalies.extend(self._detect_statistical_anomalies())
        
        if analysis_type in ['temporal', 'all']:
            anomalies.extend(self._detect_temporal_anomalies())
        
        if analysis_type in ['behavioral', 'all']:
            anomalies.extend(self._detect_behavioral_anomalies())
        
        self.analysis_results['anomalies'] = anomalies
        print(f"[+] Found {len(anomalies)} anomalies")
        
        return anomalies

    def _detect_statistical_anomalies(self) -> List[Dict[str, Any]]:
        """Detect statistical anomalies using z-score analysis."""
        anomalies = []
        
        # Analyze IP request frequency
        ip_counts = list(self.analysis_results['top_ips'].values())
        if len(ip_counts) > 1:
            mean_requests = statistics.mean(ip_counts)
            stdev_requests = statistics.stdev(ip_counts) if len(ip_counts) > 1 else 0
            
            if stdev_requests > 0:
                threshold = 2.5  # Z-score threshold
                
                for ip, count in self.analysis_results['top_ips'].items():
                    z_score = (count - mean_requests) / stdev_requests
                    
                    if abs(z_score) > threshold:
                        anomalies.append({
                            'type': 'statistical',
                            'category': 'unusual_request_volume',
                            'description': f'IP {ip} has unusual request volume',
                            'details': {
                                'ip_address': ip,
                                'request_count': count,
                                'z_score': round(z_score, 2),
                                'severity': 'HIGH' if z_score > 3 else 'MEDIUM'
                            }
                        })
        
        # Analyze status code distribution
        total_requests = sum(self.analysis_results['status_codes'].values())
        if total_requests > 0:
            error_rate = (self.analysis_results['status_codes'].get('404', 0) + 
                         self.analysis_results['status_codes'].get('500', 0)) / total_requests
            
            if error_rate > 0.1:  # More than 10% error rate
                anomalies.append({
                    'type': 'statistical',
                    'category': 'high_error_rate',
                    'description': f'High error rate detected: {error_rate:.1%}',
                    'details': {
                        'error_rate': round(error_rate, 3),
                        'total_requests': total_requests,
                        'severity': 'HIGH' if error_rate > 0.2 else 'MEDIUM'
                    }
                })
        
        return anomalies

    def _detect_temporal_anomalies(self) -> List[Dict[str, Any]]:
        """Detect temporal anomalies in request patterns."""
        anomalies = []
        
        # This would require time-series analysis of log entries
        # For now, return placeholder indicating this feature
        anomalies.append({
            'type': 'temporal',
            'category': 'analysis_placeholder',
            'description': 'Temporal analysis requires time-series data processing',
            'details': {
                'note': 'Feature available with timestamp parsing enabled',
                'severity': 'INFO'
            }
        })
        
        return anomalies

    def _detect_behavioral_anomalies(self) -> List[Dict[str, Any]]:
        """Detect behavioral anomalies in user patterns."""
        anomalies = []
        
        # Detect potential bot behavior
        for user_agent, count in self.analysis_results['top_user_agents'].most_common(10):
            if count > 100 and any(bot_indicator in user_agent.lower() for bot_indicator in 
                                  ['bot', 'crawler', 'spider', 'scraper']):
                anomalies.append({
                    'type': 'behavioral',
                    'category': 'bot_activity',
                    'description': f'High-volume bot activity detected',
                    'details': {
                        'user_agent': user_agent,
                        'request_count': count,
                        'severity': 'LOW'
                    }
                })
        
        return anomalies

    def generate_timeline_analysis(self) -> Dict[str, Any]:
        """Generate timeline analysis of log events."""
        print("[+] Generating timeline analysis...")
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get entries with timestamps
        cursor.execute('''
            SELECT timestamp, status_code, COUNT(*) as count
            FROM log_entries 
            WHERE timestamp != ''
            GROUP BY timestamp, status_code
            ORDER BY timestamp
        ''')
        
        timeline_data = cursor.fetchall()
        conn.close()
        
        timeline = {
            'total_timepoints': len(timeline_data),
            'time_range': {},
            'hourly_distribution': defaultdict(int),
            'status_timeline': defaultdict(list)
        }
        
        if timeline_data:
            timestamps = [row[0] for row in timeline_data]
            timeline['time_range'] = {
                'start': min(timestamps),
                'end': max(timestamps)
            }
            
            # Process timeline data
            for timestamp, status_code, count in timeline_data:
                # Extract hour for distribution analysis
                try:
                    # Simple hour extraction (assumes format contains hour)
                    hour_match = re.search(r'(\d{2}):\d{2}:\d{2}', timestamp)
                    if hour_match:
                        hour = int(hour_match.group(1))
                        timeline['hourly_distribution'][hour] += count
                except:
                    pass
                
                timeline['status_timeline'][status_code].append({
                    'timestamp': timestamp,
                    'count': count
                })
        
        self.analysis_results['timeline_analysis'] = timeline
        return timeline

    def generate_report(self, format_type: str = 'json', output_file: str = None) -> str:
        """
        Generate comprehensive analysis report.
        
        Args:
            format_type: Output format ('json', 'csv', 'html')
            output_file: Output file path (optional)
            
        Returns:
            Report content or file path
        """
        print(f"[+] Generating {format_type.upper()} report...")
        
        # Ensure we have fresh timeline analysis
        self.generate_timeline_analysis()
        
        # Compile comprehensive report data
        report_data = {
            'analysis_summary': {
                'total_entries_analyzed': self.analysis_results['total_entries'],
                'threats_detected': len([t for threats in self.analysis_results['threats_detected'].values() for t in threats]),
                'anomalies_found': len(self.analysis_results['anomalies']),
                'analysis_timestamp': datetime.now().isoformat()
            },
            'traffic_analysis': {
                'top_ip_addresses': dict(self.analysis_results['top_ips'].most_common(10)),
                'status_code_distribution': dict(self.analysis_results['status_codes']),
                'top_user_agents': dict(self.analysis_results['top_user_agents'].most_common(5))
            },
            'security_analysis': {
                'threats_by_type': dict(self.analysis_results['threats_detected']),
                'anomalies': self.analysis_results['anomalies']
            },
            'temporal_analysis': self.analysis_results['timeline_analysis']
        }
        
        if format_type == 'json':
            content = json.dumps(report_data, indent=2, default=str)
        elif format_type == 'csv':
            content = self._generate_csv_report(report_data)
        elif format_type == 'html':
            content = self._generate_html_report(report_data)
        else:
            raise ValueError(f"Unsupported format: {format_type}")
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"[+] Report saved to: {output_file}")
            return output_file
        
        return content

    def _generate_csv_report(self, report_data: Dict[str, Any]) -> str:
        """Generate CSV format report."""
        import io
        
        output = io.StringIO()
        
        # Summary section
        output.write("Log Analysis Summary\n")
        output.write("Metric,Value\n")
        for key, value in report_data['analysis_summary'].items():
            output.write(f"{key},{value}\n")
        
        output.write("\nTop IP Addresses\n")
        output.write("IP Address,Request Count\n")
        for ip, count in report_data['traffic_analysis']['top_ip_addresses'].items():
            output.write(f"{ip},{count}\n")
        
        output.write("\nStatus Code Distribution\n")
        output.write("Status Code,Count\n")
        for code, count in report_data['traffic_analysis']['status_code_distribution'].items():
            output.write(f"{code},{count}\n")
        
        return output.getvalue()

    def _generate_html_report(self, report_data: Dict[str, Any]) -> str:
        """Generate HTML format report."""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Log Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #1a1a1a; color: #e0e0e0; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                   color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .section {{ background-color: #2d2d2d; padding: 20px; margin-bottom: 20px; 
                    border-radius: 8px; border: 1px solid #444; }}
        .metric {{ display: inline-block; margin: 10px; padding: 15px; 
                   background-color: #3d3d3d; border-radius: 6px; min-width: 200px; }}
        .metric-label {{ font-weight: bold; color: #bb86fc; }}
        .metric-value {{ font-size: 1.2em; color: #03dac6; }}
        .table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        .table th, .table td {{ padding: 8px; text-align: left; border-bottom: 1px solid #444; }}
        .table th {{ background-color: #444; color: #bb86fc; }}
        .threat-high {{ color: #cf6679; font-weight: bold; }}
        .threat-medium {{ color: #f39c12; font-weight: bold; }}
        .threat-low {{ color: #03dac6; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Log Analysis Report</h1>
            <p>Generated on: {timestamp}</p>
        </div>
        
        <div class="section">
            <h2>Analysis Summary</h2>
            <div class="metric">
                <div class="metric-label">Total Entries</div>
                <div class="metric-value">{total_entries}</div>
            </div>
            <div class="metric">
                <div class="metric-label">Threats Detected</div>
                <div class="metric-value">{threats_detected}</div>
            </div>
            <div class="metric">
                <div class="metric-label">Anomalies Found</div>
                <div class="metric-value">{anomalies_found}</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Top IP Addresses</h2>
            <table class="table">
                <thead>
                    <tr><th>IP Address</th><th>Request Count</th></tr>
                </thead>
                <tbody>
                    {ip_table_rows}
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>Status Code Distribution</h2>
            <table class="table">
                <thead>
                    <tr><th>Status Code</th><th>Count</th><th>Description</th></tr>
                </thead>
                <tbody>
                    {status_table_rows}
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>Security Analysis</h2>
            {security_content}
        </div>
    </div>
</body>
</html>
        """
        
        # Generate IP table rows
        ip_rows = ""
        for ip, count in report_data['traffic_analysis']['top_ip_addresses'].items():
            ip_rows += f"<tr><td>{ip}</td><td>{count}</td></tr>"
        
        # Generate status code table rows
        status_rows = ""
        for code, count in report_data['traffic_analysis']['status_code_distribution'].items():
            description = self.http_status_codes.get(code, 'Unknown')
            status_rows += f"<tr><td>{code}</td><td>{count}</td><td>{description}</td></tr>"
        
        # Generate security content
        security_content = "<h3>Threats Detected</h3>"
        if report_data['security_analysis']['threats_by_type']:
            for threat_type, threats in report_data['security_analysis']['threats_by_type'].items():
                security_content += f"<p><strong>{threat_type.replace('_', ' ').title()}:</strong> {len(threats)} instances</p>"
        else:
            security_content += "<p>No threats detected.</p>"
        
        security_content += "<h3>Anomalies</h3>"
        if report_data['security_analysis']['anomalies']:
            for anomaly in report_data['security_analysis']['anomalies']:
                severity_class = f"threat-{anomaly['details'].get('severity', 'low').lower()}"
                security_content += f"<p class='{severity_class}'><strong>{anomaly['category']}:</strong> {anomaly['description']}</p>"
        else:
            security_content += "<p>No anomalies detected.</p>"
        
        return html_template.format(
            timestamp=report_data['analysis_summary']['analysis_timestamp'],
            total_entries=report_data['analysis_summary']['total_entries_analyzed'],
            threats_detected=report_data['analysis_summary']['threats_detected'],
            anomalies_found=report_data['analysis_summary']['anomalies_found'],
            ip_table_rows=ip_rows,
            status_table_rows=status_rows,
            security_content=security_content
        )

    def search_logs(self, query: str, search_type: str = 'regex') -> List[Dict[str, Any]]:
        """
        Search through parsed logs with various query types.
        
        Args:
            query: Search query
            search_type: Type of search ('regex', 'text', 'ip', 'status')
            
        Returns:
            List of matching log entries
        """
        print(f"[+] Searching logs: {query} (type: {search_type})")
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if search_type == 'regex':
            # Use REGEXP in SQLite (requires compilation with REGEXP support)
            cursor.execute("SELECT * FROM log_entries WHERE raw_entry REGEXP ?", (query,))
        elif search_type == 'text':
            cursor.execute("SELECT * FROM log_entries WHERE raw_entry LIKE ?", (f'%{query}%',))
        elif search_type == 'ip':
            cursor.execute("SELECT * FROM log_entries WHERE ip_address = ?", (query,))
        elif search_type == 'status':
            cursor.execute("SELECT * FROM log_entries WHERE status_code = ?", (query,))
        else:
            cursor.execute("SELECT * FROM log_entries WHERE raw_entry LIKE ?", (f'%{query}%',))
        
        results = cursor.fetchall()
        conn.close()
        
        # Convert to dictionaries
        columns = ['id', 'timestamp', 'source_file', 'log_type', 'ip_address', 
                  'method', 'url', 'status_code', 'size', 'user_agent', 'raw_entry', 
                  'threats', 'created_at']
        
        search_results = []
        for row in results:
            entry = dict(zip(columns, row))
            # Parse threats JSON
            if entry['threats']:
                try:
                    entry['threats'] = json.loads(entry['threats'])
                except:
                    entry['threats'] = {}
            search_results.append(entry)
        
        print(f"[+] Found {len(search_results)} matching entries")
        return search_results


def main():
    """Main CLI interface for the Log Parser."""
    parser = argparse.ArgumentParser(
        description="Log Parser - Intelligent Log Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python log_parser.py analyze access.log --format apache_common
  python log_parser.py search "404" --type status --output results.json
  python log_parser.py detect-anomalies --type statistical
  python log_parser.py report --format html --output report.html
  python log_parser.py timeline --show-graph

Educational Use Only - Ensure proper authorization before analyzing logs.
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze log files')
    analyze_parser.add_argument('files', nargs='+', help='Log files to analyze')
    analyze_parser.add_argument('--format', choices=['auto', 'apache_common', 'apache_combined', 
                                                    'nginx_access', 'syslog', 'windows_event', 'custom'],
                               default='auto', help='Log format type')
    analyze_parser.add_argument('--encoding', default='utf-8', help='File encoding')
    analyze_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    # Search command
    search_parser = subparsers.add_parser('search', help='Search through logs')
    search_parser.add_argument('query', help='Search query')
    search_parser.add_argument('--type', choices=['regex', 'text', 'ip', 'status'], 
                              default='text', help='Search type')
    search_parser.add_argument('--output', help='Output file for results')
    search_parser.add_argument('--limit', type=int, default=100, help='Maximum results to return')
    
    # Anomaly detection command
    anomaly_parser = subparsers.add_parser('detect-anomalies', help='Detect anomalies in logs')
    anomaly_parser.add_argument('--type', choices=['statistical', 'temporal', 'behavioral', 'all'],
                               default='statistical', help='Anomaly detection type')
    anomaly_parser.add_argument('--output', help='Output file for anomalies')
    
    # Report generation command
    report_parser = subparsers.add_parser('report', help='Generate analysis report')
    report_parser.add_argument('--format', choices=['json', 'csv', 'html'], 
                              default='json', help='Report format')
    report_parser.add_argument('--output', help='Output file for report')
    
    # Timeline analysis command
    timeline_parser = subparsers.add_parser('timeline', help='Generate timeline analysis')
    timeline_parser.add_argument('--output', help='Output file for timeline data')
    timeline_parser.add_argument('--show-graph', action='store_true', help='Show visual timeline (requires matplotlib)')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize log parser
    log_parser = LogParser()
    
    try:
        if args.command == 'analyze':
            print(f"[+] Starting log analysis of {len(args.files)} file(s)...")
            
            for file_path in args.files:
                result = log_parser.parse_log_file(file_path, args.format, args.encoding)
                
                if 'error' in result:
                    print(f"[-] Error processing {file_path}: {result['error']}")
                    continue
                
                print(f"[+] File: {file_path}")
                print(f"    Entries parsed: {result['entries_parsed']}")
                print(f"    Entries failed: {result['entries_failed']}")
                print(f"    Parsing time: {result['parsing_time']:.2f}s")
                
                if result['threats_found']:
                    print(f"    Threats found: {sum(len(v) for v in result['threats_found'].values())}")
                    if args.verbose:
                        for threat_type, threats in result['threats_found'].items():
                            print(f"      {threat_type}: {len(threats)} instances")
            
            print(f"\n[+] Analysis complete. Total entries: {log_parser.analysis_results['total_entries']}")
            
        elif args.command == 'search':
            results = log_parser.search_logs(args.query, args.type)
            
            # Limit results
            if len(results) > args.limit:
                results = results[:args.limit]
                print(f"[!] Results limited to {args.limit} entries")
            
            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=2, default=str)
                print(f"[+] Search results saved to: {args.output}")
            else:
                for entry in results:
                    print(f"[{entry['timestamp']}] {entry['raw_entry'][:100]}...")
            
        elif args.command == 'detect-anomalies':
            anomalies = log_parser.detect_anomalies(args.type)
            
            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump(anomalies, f, indent=2, default=str)
                print(f"[+] Anomalies saved to: {args.output}")
            else:
                for anomaly in anomalies:
                    severity = anomaly['details'].get('severity', 'UNKNOWN')
                    print(f"[{severity}] {anomaly['category']}: {anomaly['description']}")
            
        elif args.command == 'report':
            report_content = log_parser.generate_report(args.format, args.output)
            
            if not args.output:
                print(report_content)
            
        elif args.command == 'timeline':
            timeline = log_parser.generate_timeline_analysis()
            
            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump(timeline, f, indent=2, default=str)
                print(f"[+] Timeline analysis saved to: {args.output}")
            else:
                print(f"Timeline Analysis:")
                print(f"  Total timepoints: {timeline['total_timepoints']}")
                if timeline['time_range']:
                    print(f"  Time range: {timeline['time_range']['start']} to {timeline['time_range']['end']}")
                
                if timeline['hourly_distribution']:
                    print(f"  Hourly distribution:")
                    for hour in sorted(timeline['hourly_distribution'].keys()):
                        count = timeline['hourly_distribution'][hour]
                        print(f"    {hour:02d}:00 - {count} requests")
        
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
    except Exception as e:
        print(f"[-] Error: {str(e)}")
        if args.command == 'analyze' and hasattr(args, 'verbose') and args.verbose:
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main()