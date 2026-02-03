@echo off
REM DepGuard Scanner for C:\Users\cczin\dependency-bad
REM Batch script to scan all services

setlocal
set DEPGUARD_PATH=C:\Users\cczin\appservice-scan
set TARGET_PATH=C:\Users\cczin\dependency-bad
set REPORTS_DIR=%DEPGUARD_PATH%\reports

REM Create reports directory
if not exist "%REPORTS_DIR%" mkdir "%REPORTS_DIR%"

echo.
echo ========================================
echo   DepGuard Multi-Service Scanner
echo ========================================
echo.

REM Scan Next.js Frontend
echo [1/3] Scanning Next.js Frontend...
cd /d "%DEPGUARD_PATH%"
node bin\depguard.js scan --path "%TARGET_PATH%\nextjs-frontend" --reachable-only --output html --file "%REPORTS_DIR%\nextjs-report.html"
echo.

REM Scan Python Service
echo [2/3] Scanning Python Service...
node bin\depguard.js scan --path "%TARGET_PATH%\python-service" --reachable-only --output html --file "%REPORTS_DIR%\python-report.html"
echo.

REM Scan Java Backend
echo [3/3] Scanning Java Backend...
node bin\depguard.js scan --path "%TARGET_PATH%\java-backend" --reachable-only --output html --file "%REPORTS_DIR%\java-report.html"
echo.

echo ========================================
echo   Scan Complete!
echo ========================================
echo.
echo Reports saved to: %REPORTS_DIR%
echo.
echo   - Next.js: nextjs-report.html
echo   - Python:  python-report.html
echo   - Java:    java-report.html
echo.

REM Open reports folder
start "" "%REPORTS_DIR%"

pause
