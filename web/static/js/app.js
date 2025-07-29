/**
 * Log Parser Web Interface JavaScript
 * ===================================
 * 
 * Interactive frontend for the Log Parser tool providing real-time analysis,
 * drag-and-drop file upload, and comprehensive reporting capabilities.
 * 
 * Features:
 * - Tabbed navigation with smooth transitions
 * - Drag-and-drop file upload with validation
 * - Real-time analysis progress tracking
 * - Interactive search and filtering
 * - Dynamic data visualization
 * - Comprehensive error handling
 * 
 * Author: Samuel Tan
 * Version: 1.0
 * License: Educational Use Only
 */

class LogParserApp {
    constructor() {
        this.currentTab = 'upload';
        this.sessionData = null;
        this.uploadedFiles = [];
        this.analysisResults = null;
        
        this.init();
    }
    
    init() {
        this.setupEventListeners();
        this.setupDragAndDrop();
        this.checkSessionInfo();
        this.updateUI();
    }
    
    setupEventListeners() {
        // Tab navigation
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.switchTab(e.target.dataset.tab);
            });
        });
        
        // File upload
        document.getElementById('browse-btn').addEventListener('click', () => {
            document.getElementById('file-input').click();
        });
        
        document.getElementById('file-input').addEventListener('change', (e) => {
            this.handleFileSelect(e.target.files);
        });
        
        // Analysis
        document.getElementById('analyze-btn').addEventListener('click', () => {
            this.startAnalysis();
        });
        
        // Security analysis
        document.getElementById('detect-anomalies-btn').addEventListener('click', () => {
            this.detectAnomalies();
        });
        
        // Search
        document.getElementById('search-btn').addEventListener('click', () => {
            this.performSearch();
        });
        
        document.getElementById('search-query').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.performSearch();
            }
        });
        
        // Timeline
        document.getElementById('generate-timeline-btn').addEventListener('click', () => {
            this.generateTimeline();
        });
        
        // Report generation
        document.querySelectorAll('.format-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.generateReport(e.target.dataset.format);
            });
        });
        
        // Status message dismissal
        document.addEventListener('click', (e) => {
            if (e.target.closest('.status-message')) {
                e.target.closest('.status-message').remove();
            }
        });
    }
    
    setupDragAndDrop() {
        const uploadArea = document.getElementById('upload-area');
        
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            uploadArea.addEventListener(eventName, this.preventDefaults, false);
            document.body.addEventListener(eventName, this.preventDefaults, false);
        });
        
        ['dragenter', 'dragover'].forEach(eventName => {
            uploadArea.addEventListener(eventName, () => {
                uploadArea.classList.add('dragover');
            }, false);
        });
        
        ['dragleave', 'drop'].forEach(eventName => {
            uploadArea.addEventListener(eventName, () => {
                uploadArea.classList.remove('dragover');
            }, false);
        });
        
        uploadArea.addEventListener('drop', (e) => {
            const files = e.dataTransfer.files;
            this.handleFileSelect(files);
        }, false);
        
        // Make entire upload area clickable
        uploadArea.addEventListener('click', () => {
            document.getElementById('file-input').click();
        });
    }
    
    preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }
    
    switchTab(tabName) {
        // Update tab buttons
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
        
        // Update tab panels
        document.querySelectorAll('.tab-panel').forEach(panel => {
            panel.classList.remove('active');
        });
        document.getElementById(`${tabName}-panel`).classList.add('active');
        
        this.currentTab = tabName;
        
        // Load data for specific tabs
        if (tabName === 'analysis' && this.analysisResults) {
            this.updateAnalysisDisplay();
        }
    }
    
    handleFileSelect(files) {
        const fileArray = Array.from(files);
        const allowedExtensions = ['log', 'txt', 'access', 'error', 'out', 'syslog', 'gz', 'zip', 'json', 'csv', 'tsv'];
        const maxFileSize = 100 * 1024 * 1024; // 100MB
        
        // Validate files
        const validFiles = [];
        const errors = [];
        
        fileArray.forEach(file => {
            const extension = file.name.split('.').pop().toLowerCase();
            
            if (!allowedExtensions.includes(extension)) {
                errors.push(`${file.name}: Invalid file type. Allowed: ${allowedExtensions.join(', ')}`);
                return;
            }
            
            if (file.size > maxFileSize) {
                errors.push(`${file.name}: File too large (${(file.size / 1024 / 1024).toFixed(2)}MB > 100MB)`);
                return;
            }
            
            validFiles.push(file);
        });
        
        if (errors.length > 0) {
            this.showMessage('error', 'File validation failed:\\n' + errors.join('\\n'));
            return;
        }
        
        if (validFiles.length === 0) {
            this.showMessage('warning', 'No valid files selected.');
            return;
        }
        
        this.uploadFiles(validFiles);
    }
    
    async uploadFiles(files) {
        const progressSection = document.getElementById('progress-section');
        const progressFill = document.getElementById('progress-fill');
        const progressText = document.getElementById('progress-text');
        
        progressSection.style.display = 'block';
        progressText.textContent = 'Uploading files...';
        progressFill.style.width = '10%';
        
        const formData = new FormData();
        files.forEach(file => {
            formData.append('files', file);
        });
        
        try {
            const response = await fetch('/api/upload', {
                method: 'POST',
                body: formData
            });
            
            const result = await response.json();
            
            if (!response.ok) {
                throw new Error(result.error || 'Upload failed');
            }
            
            this.uploadedFiles = result.files;
            this.displayUploadedFiles();
            
            progressFill.style.width = '100%';
            progressText.textContent = `Successfully uploaded ${result.files_uploaded} files (${result.total_size_mb}MB)`;
            
            // Enable analysis button
            document.getElementById('analyze-btn').disabled = false;
            
            this.showMessage('success', `Successfully uploaded ${result.files_uploaded} files`);
            
        } catch (error) {
            progressFill.style.width = '0%';
            progressText.textContent = 'Upload failed';
            this.showMessage('error', `Upload failed: ${error.message}`);
        }
    }
    
    displayUploadedFiles() {
        const filesList = document.getElementById('files-list');
        const filesContainer = document.getElementById('files-container');
        
        filesList.style.display = 'block';
        filesContainer.innerHTML = '';
        
        this.uploadedFiles.forEach(file => {
            const fileItem = document.createElement('div');
            fileItem.className = 'file-item';
            fileItem.innerHTML = `
                <div class="file-info">
                    <div class="file-name">📄 ${file.filename}</div>
                    <div class="file-size">${file.size_mb} MB</div>
                </div>
            `;
            filesContainer.appendChild(fileItem);
        });
    }
    
    async startAnalysis() {
        if (this.uploadedFiles.length === 0) {
            this.showMessage('warning', 'Please upload files first.');
            return;
        }
        
        const progressSection = document.getElementById('progress-section');
        const progressFill = document.getElementById('progress-fill');
        const progressText = document.getElementById('progress-text');
        const analyzeBtn = document.getElementById('analyze-btn');
        
        progressSection.style.display = 'block';
        progressText.textContent = 'Starting log analysis...';
        progressFill.style.width = '20%';
        analyzeBtn.disabled = true;
        analyzeBtn.classList.add('loading');
        
        const logFormat = document.getElementById('log-format').value;
        const encoding = document.getElementById('encoding').value;
        
        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    format: logFormat,
                    encoding: encoding
                })
            });
            
            const result = await response.json();
            
            if (!response.ok) {
                throw new Error(result.error || 'Analysis failed');
            }
            
            this.analysisResults = result;
            
            progressFill.style.width = '100%';
            progressText.textContent = `Analysis complete! Processed ${result.total_entries} log entries`;
            
            // Update header stats
            this.updateHeaderStats();
            
            // Update threat patterns
            this.updateThreatPatterns();
            
            this.showMessage('success', `Analysis complete: ${result.total_entries} entries processed`);
            
            // Switch to analysis tab
            this.switchTab('analysis');
            
        } catch (error) {
            progressFill.style.width = '0%';
            progressText.textContent = 'Analysis failed';
            this.showMessage('error', `Analysis failed: ${error.message}`);
        } finally {
            analyzeBtn.disabled = false;
            analyzeBtn.classList.remove('loading');
        }
    }
    
    updateHeaderStats() {
        if (!this.analysisResults) return;
        
        document.getElementById('total-entries').textContent = this.analysisResults.total_entries || 0;
        
        const threatsCount = Object.values(this.analysisResults.threats_summary || {})
            .reduce((sum, count) => sum + count, 0);
        document.getElementById('threats-found').textContent = threatsCount;
    }
    
    updateAnalysisDisplay() {
        if (!this.analysisResults) return;
        
        // Update overview stats
        const overviewStats = document.getElementById('overview-stats');
        const stats = overviewStats.querySelectorAll('.stat-box');
        
        if (stats.length >= 4) {
            stats[0].querySelector('.stat-number').textContent = this.analysisResults.files_analyzed?.length || 0;
            stats[1].querySelector('.stat-number').textContent = this.analysisResults.total_entries || 0;
            stats[2].querySelector('.stat-number').textContent = `${(this.analysisResults.total_parsing_time || 0).toFixed(2)}s`;
            
            const successRate = this.analysisResults.total_entries > 0 ? 
                ((this.analysisResults.total_entries / (this.analysisResults.total_entries + (this.analysisResults.total_failures || 0))) * 100).toFixed(1) : 100;
            stats[3].querySelector('.stat-number').textContent = `${successRate}%`;
        }
        
        // Update top IPs
        this.updateListDisplay('top-ips', this.analysisResults.top_ips);
        
        // Update status codes
        this.updateStatusCodes(this.analysisResults.status_codes);
        
        // Update user agents
        this.updateListDisplay('user-agents', this.analysisResults.top_user_agents);
    }
    
    updateListDisplay(containerId, data) {
        const container = document.getElementById(containerId);
        
        if (!data || Object.keys(data).length === 0) {
            container.innerHTML = '<p class="no-data">No data available.</p>';
            return;
        }
        
        const sortedData = Object.entries(data).sort((a, b) => b[1] - a[1]);
        
        container.innerHTML = sortedData.map(([key, value]) => `
            <div class="list-item">
                <span class="item-label">${this.escapeHtml(key)}</span>
                <span class="item-value">${value}</span>
            </div>
        `).join('');
    }
    
    updateStatusCodes(data) {
        const container = document.getElementById('status-codes');
        
        if (!data || Object.keys(data).length === 0) {
            container.innerHTML = '<p class="no-data">No data available.</p>';
            return;
        }
        
        const statusCodeNames = {
            '200': 'OK', '201': 'Created', '204': 'No Content',
            '301': 'Moved Permanently', '302': 'Found', '304': 'Not Modified',
            '400': 'Bad Request', '401': 'Unauthorized', '403': 'Forbidden',
            '404': 'Not Found', '405': 'Method Not Allowed', '429': 'Too Many Requests',
            '500': 'Internal Server Error', '502': 'Bad Gateway', '503': 'Service Unavailable'
        };
        
        const sortedData = Object.entries(data).sort((a, b) => b[1] - a[1]);
        
        container.innerHTML = sortedData.map(([code, count]) => `
            <div class="list-item">
                <span class="item-label">${code} - ${statusCodeNames[code] || 'Unknown'}</span>
                <span class="item-value">${count}</span>
            </div>
        `).join('');
    }
    
    updateThreatPatterns() {
        if (!this.analysisResults || !this.analysisResults.threats_summary) return;
        
        const patterns = document.querySelectorAll('.pattern-count');
        patterns.forEach(pattern => {
            const patternType = pattern.dataset.pattern;
            const count = this.analysisResults.threats_summary[patternType] || 0;
            pattern.textContent = count;
        });
        
        // Update threat summary
        const threatSummary = document.getElementById('threat-summary');
        const threats = this.analysisResults.threats_summary;
        
        if (Object.keys(threats).length === 0) {
            threatSummary.innerHTML = '<p class="no-data">No threats detected.</p>';
            return;
        }
        
        threatSummary.innerHTML = Object.entries(threats).map(([type, count]) => `
            <div class="threat-item">
                <span class="threat-name">${type.replace('_', ' ').toUpperCase()}</span>
                <span class="threat-count">${count}</span>
            </div>
        `).join('');
    }
    
    async detectAnomalies() {
        if (!this.analysisResults) {
            this.showMessage('warning', 'Please run analysis first.');
            return;
        }
        
        const button = document.getElementById('detect-anomalies-btn');
        const anomalyType = document.getElementById('anomaly-type').value;
        
        button.disabled = true;
        button.classList.add('loading');
        
        try {
            const response = await fetch('/api/detect-anomalies', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    type: anomalyType
                })
            });
            
            const result = await response.json();
            
            if (!response.ok) {
                throw new Error(result.error || 'Anomaly detection failed');
            }
            
            this.displayAnomalies(result.anomalies);
            document.getElementById('anomalies-found').textContent = result.summary.total_anomalies;
            
            this.showMessage('success', `Found ${result.summary.total_anomalies} anomalies`);
            
        } catch (error) {
            this.showMessage('error', `Anomaly detection failed: ${error.message}`);
        } finally {
            button.disabled = false;
            button.classList.remove('loading');
        }
    }
    
    displayAnomalies(anomalies) {
        const container = document.getElementById('anomalies-container');
        
        if (!anomalies || anomalies.length === 0) {
            container.innerHTML = '<p class="no-data">No anomalies detected.</p>';
            return;
        }
        
        container.innerHTML = anomalies.map(anomaly => {
            const severity = anomaly.details?.severity?.toLowerCase() || 'low';
            return `
                <div class="anomaly-item ${severity}-severity">
                    <div class="anomaly-title">${anomaly.category.replace('_', ' ').toUpperCase()}</div>
                    <div class="anomaly-description">${this.escapeHtml(anomaly.description)}</div>
                    <div class="anomaly-details">Severity: ${anomaly.details?.severity || 'Unknown'}</div>
                </div>
            `;
        }).join('');
    }
    
    async performSearch() {
        const query = document.getElementById('search-query').value.trim();
        
        if (!query) {
            this.showMessage('warning', 'Please enter a search query.');
            return;
        }
        
        if (!this.analysisResults) {
            this.showMessage('warning', 'Please run analysis first.');
            return;
        }
        
        const searchType = document.getElementById('search-type').value;
        const resultLimit = parseInt(document.getElementById('result-limit').value);
        const searchBtn = document.getElementById('search-btn');
        
        searchBtn.disabled = true;
        searchBtn.classList.add('loading');
        
        try {
            const response = await fetch('/api/search', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    query: query,
                    type: searchType,
                    limit: resultLimit
                })
            });
            
            const result = await response.json();
            
            if (!response.ok) {
                throw new Error(result.error || 'Search failed');
            }
            
            this.displaySearchResults(result);
            
        } catch (error) {
            this.showMessage('error', `Search failed: ${error.message}`);
        } finally {
            searchBtn.disabled = false;
            searchBtn.classList.remove('loading');
        }
    }
    
    displaySearchResults(result) {
        const summary = document.getElementById('search-summary');
        const entries = document.getElementById('search-entries');
        
        summary.style.display = 'block';
        document.getElementById('search-count').textContent = result.total_results;
        document.getElementById('search-term').textContent = result.query;
        
        if (!result.results || result.results.length === 0) {
            entries.innerHTML = '<p class="no-data">No matching entries found.</p>';
            return;
        }
        
        entries.innerHTML = result.results.map(entry => `
            <div class="search-entry">
                <div class="entry-meta">
                    ${entry.timestamp || 'No timestamp'} | 
                    ${entry.ip_address || 'No IP'} | 
                    ${entry.status_code || 'No status'}
                </div>
                <div class="entry-content">${this.escapeHtml(entry.raw_entry || 'No content')}</div>
            </div>
        `).join('');
        
        if (result.limited) {
            const limitNotice = document.createElement('div');
            limitNotice.className = 'no-data';
            limitNotice.textContent = `Results limited to ${result.limit} entries. Refine your search for more specific results.`;
            entries.appendChild(limitNotice);
        }
    }
    
    async generateTimeline() {
        if (!this.analysisResults) {
            this.showMessage('warning', 'Please run analysis first.');
            return;
        }
        
        const button = document.getElementById('generate-timeline-btn');
        button.disabled = true;
        button.classList.add('loading');
        
        try {
            const response = await fetch('/api/timeline');
            const result = await response.json();
            
            if (!response.ok) {
                throw new Error(result.error || 'Timeline generation failed');
            }
            
            this.displayTimeline(result.timeline);
            this.showMessage('success', 'Timeline generated successfully');
            
        } catch (error) {
            this.showMessage('error', `Timeline generation failed: ${error.message}`);
        } finally {
            button.disabled = false;
            button.classList.remove('loading');
        }
    }
    
    displayTimeline(timeline) {
        // Update timeline summary
        const summary = document.getElementById('timeline-summary');
        summary.innerHTML = `
            <div class="timeline-stat">
                <span class="timeline-label">Total Timepoints</span>
                <span class="timeline-value">${timeline.total_timepoints || 0}</span>
            </div>
            <div class="timeline-stat">
                <span class="timeline-label">Time Range Start</span>
                <span class="timeline-value">${timeline.time_range?.start || 'N/A'}</span>
            </div>
            <div class="timeline-stat">
                <span class="timeline-label">Time Range End</span>
                <span class="timeline-value">${timeline.time_range?.end || 'N/A'}</span>
            </div>
        `;
        
        // Update hourly chart
        this.displayHourlyChart(timeline.hourly_distribution);
        
        // Update timeline events
        this.displayTimelineEvents(timeline.status_timeline);
    }
    
    displayHourlyChart(hourlyData) {
        const chart = document.getElementById('hourly-chart');
        
        if (!hourlyData || Object.keys(hourlyData).length === 0) {
            chart.innerHTML = '<p class="no-data">No hourly data available.</p>';
            return;
        }
        
        const maxCount = Math.max(...Object.values(hourlyData));
        
        chart.innerHTML = '';
        for (let hour = 0; hour < 24; hour++) {
            const count = hourlyData[hour] || 0;
            const percentage = maxCount > 0 ? (count / maxCount) * 100 : 0;
            
            const hourBar = document.createElement('div');
            hourBar.className = 'hour-bar';
            hourBar.innerHTML = `
                <div class="hour-label">${hour.toString().padStart(2, '0')}:00</div>
                <div class="hour-graph">
                    <div class="hour-fill" style="width: ${percentage}%"></div>
                </div>
                <div class="hour-count">${count}</div>
            `;
            chart.appendChild(hourBar);
        }
    }
    
    displayTimelineEvents(statusTimeline) {
        const events = document.getElementById('timeline-events');
        
        if (!statusTimeline || Object.keys(statusTimeline).length === 0) {
            events.innerHTML = '<p class="no-data">No timeline events available.</p>';
            return;
        }
        
        events.innerHTML = Object.entries(statusTimeline).map(([status, eventList]) => `
            <div class="timeline-stat">
                <span class="timeline-label">Status ${status} Events</span>
                <span class="timeline-value">${eventList.length}</span>
            </div>
        `).join('');
    }
    
    async generateReport(format) {
        if (!this.analysisResults) {
            this.showMessage('warning', 'Please run analysis first.');
            return;
        }
        
        const button = document.querySelector(`[data-format="${format}"]`);
        button.disabled = true;
        button.classList.add('loading');
        
        try {
            const response = await fetch('/api/report', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    format: format
                })
            });
            
            const result = await response.json();
            
            if (!response.ok) {
                throw new Error(result.error || 'Report generation failed');
            }
            
            this.addGeneratedReport(result.report, result.download_url);
            this.showMessage('success', `${format.toUpperCase()} report generated successfully`);
            
        } catch (error) {
            this.showMessage('error', `Report generation failed: ${error.message}`);
        } finally {
            button.disabled = false;
            button.classList.remove('loading');
        }
    }
    
    addGeneratedReport(report, downloadUrl) {
        const reportsList = document.getElementById('reports-list');
        
        // Remove "no data" message if present
        const noData = reportsList.querySelector('.no-data');
        if (noData) {
            noData.remove();
        }
        
        const reportItem = document.createElement('div');
        reportItem.className = 'report-item';
        reportItem.innerHTML = `
            <div class="report-info">
                <div class="report-name">📄 ${report.filename}</div>
                <div class="report-meta">
                    ${report.format.toUpperCase()} • ${(report.size / 1024).toFixed(1)} KB • 
                    ${new Date(report.generated_at).toLocaleString()}
                </div>
            </div>
            <a href="${downloadUrl}" class="download-btn">
                ⬇️ Download
            </a>
        `;
        
        reportsList.appendChild(reportItem);
    }
    
    async checkSessionInfo() {
        try {
            const response = await fetch('/api/session-info');
            const result = await response.json();
            
            this.sessionData = result;
            
            if (result.has_data) {
                // Update UI based on existing session data
                if (result.total_entries > 0) {
                    document.getElementById('total-entries').textContent = result.total_entries;
                }
            }
            
        } catch (error) {
            console.log('Session check failed:', error.message);
        }
    }
    
    showMessage(type, message) {
        const messagesContainer = document.getElementById('status-messages');
        
        const messageElement = document.createElement('div');
        messageElement.className = `status-message ${type}`;
        messageElement.textContent = message;
        
        messagesContainer.appendChild(messageElement);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (messageElement.parentNode) {
                messageElement.remove();
            }
        }, 5000);
    }
    
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    updateUI() {
        // Update UI based on current state
        if (this.uploadedFiles.length > 0) {
            document.getElementById('analyze-btn').disabled = false;
        }
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.logParserApp = new LogParserApp();
});

// Handle window resize for responsive design
window.addEventListener('resize', () => {
    // Refresh any charts or visualizations that need resizing
    if (window.logParserApp && window.logParserApp.currentTab === 'timeline') {
        // Refresh timeline charts if needed
    }
});

// Handle beforeunload to warn about unsaved data
window.addEventListener('beforeunload', (e) => {
    if (window.logParserApp && window.logParserApp.uploadedFiles.length > 0) {
        e.preventDefault();
        e.returnValue = 'You have uploaded files that may be lost. Are you sure you want to leave?';
        return e.returnValue;
    }
});

// Service worker registration for offline support (optional)
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        // Uncomment to enable service worker
        // navigator.serviceWorker.register('/sw.js')
        //     .then(registration => console.log('SW registered'))
        //     .catch(error => console.log('SW registration failed'));
    });
}

// Export for testing purposes
if (typeof module !== 'undefined' && module.exports) {
    module.exports = LogParserApp;
}