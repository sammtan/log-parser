@echo off
REM Log Parser Web Interface Startup Script
REM =======================================
REM 
REM This script starts the Flask web interface for the Log Parser tool
REM on Windows systems with automatic dependency checking and setup.
REM
REM Features:
REM - Automatic Python environment detection
REM - Dependency installation and verification
REM - Port availability checking
REM - Professional startup sequence
REM
REM Author: Samuel Tan
REM Version: 1.0
REM Educational Use Only

title Log Parser - Web Interface Startup

echo.
echo ================================================================
echo                    Log Parser Web Interface
echo ================================================================
echo.
echo Starting intelligent log analysis web application...
echo Version: 1.0 ^| Author: Samuel Tan
echo Educational Use Only - Ensure proper authorization
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo.
    echo Please install Python 3.7+ from https://python.org
    echo Make sure to add Python to your system PATH during installation
    echo.
    pause
    exit /b 1
)

echo [+] Python detected: 
python --version

REM Check Python version (basic check)
python -c "import sys; exit(0 if sys.version_info >= (3, 7) else 1)" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python 3.7 or higher is required
    echo Current version is too old for this application
    echo.
    pause
    exit /b 1
)

echo [+] Python version is compatible

REM Change to the web directory
cd /d "%~dp0web"
if errorlevel 1 (
    echo [ERROR] Could not change to web directory
    echo Make sure this script is in the log-parser root directory
    echo.
    pause
    exit /b 1
)

echo [+] Working directory: %CD%

REM Check if required directories exist
if not exist "templates" (
    echo [ERROR] Templates directory not found
    echo Web interface files may be missing or corrupted
    echo.
    pause
    exit /b 1
)

if not exist "static" (
    echo [ERROR] Static files directory not found
    echo Web interface assets may be missing or corrupted
    echo.
    pause
    exit /b 1
)

echo [+] Web interface files verified

REM Create required directories
if not exist "uploads" mkdir uploads
if not exist "reports" mkdir reports

echo [+] Required directories created/verified

REM Check if Flask is installed
python -c "import flask" >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Flask not found, installing dependencies...
    echo.
    
    REM Try to install requirements
    python -m pip install Flask==2.3.3 Werkzeug==2.3.7 Jinja2==3.1.2 MarkupSafe==2.1.3
    if errorlevel 1 (
        echo [ERROR] Failed to install required dependencies
        echo.
        echo Please install manually using:
        echo   pip install -r ../requirements.txt
        echo.
        pause
        exit /b 1
    )
    
    echo [+] Dependencies installed successfully
) else (
    echo [+] Flask is available
)

REM Verify core modules are importable
python -c "import sys, os; sys.path.append(os.path.join('..', 'src')); import log_parser" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Log Parser core module not found
    echo Make sure log_parser.py exists in the src directory
    echo.
    pause
    exit /b 1
)

echo [+] Core modules verified

REM Check if port 5000 is available (basic check)
netstat -an | find "0.0.0.0:5000" >nul 2>&1
if not errorlevel 1 (
    echo [WARNING] Port 5000 appears to be in use
    echo The web interface may fail to start or use a different port
    echo.
)

echo [+] Port availability checked

echo.
echo ================================================================
echo                        Starting Web Server
echo ================================================================
echo.
echo Web Interface Features:
echo   - Drag-and-drop file upload with validation
echo   - Real-time log parsing and analysis
echo   - Interactive threat detection and reporting
echo   - Timeline analysis and anomaly detection
echo   - Multi-format export (JSON, CSV, HTML)
echo.
echo Access the web interface at: http://localhost:5000
echo Press Ctrl+C to stop the server
echo.
echo Educational Use Only - Ensure proper authorization before
echo analyzing logs from systems you do not own or administer.
echo.
echo ================================================================
echo.

REM Start the Flask development server
python app.py

REM Handle server shutdown
echo.
echo ================================================================
echo                        Server Stopped
echo ================================================================
echo.
echo The Log Parser web interface has been stopped.
echo.
echo Session data and uploaded files are automatically cleaned up
echo after 2 hours of inactivity for security purposes.
echo.
echo To restart the web interface, run this script again.
echo.

pause