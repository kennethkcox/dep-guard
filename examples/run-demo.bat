@echo off
setlocal enabledelayedexpansion

REM DepGuard v2.0 Interactive Demo Script for Windows
REM This script walks you through the complete workflow

set DEMO_DIR=%~dp0vulnerable-test-app
set ROOT_DIR=%~dp0..
set DEPGUARD=node "%ROOT_DIR%\bin\depguard.js"

echo.
echo ================================================================
echo.
echo              DepGuard v2.0 Interactive Demo
echo.
echo   Data Flow Analysis + Machine Learning Risk Prediction
echo.
echo ================================================================
echo.

if not exist "%DEMO_DIR%" (
    echo Error: Demo app not found at %DEMO_DIR%
    echo Please run from the examples directory
    exit /b 1
)

cd "%DEMO_DIR%"

REM Clean up previous runs
if exist .depguard-cache rmdir /s /q .depguard-cache 2>nul
if exist .depguard-feedback rmdir /s /q .depguard-feedback 2>nul
if exist .depguard-models rmdir /s /q .depguard-models 2>nul

echo ================================================================
echo  Step 1: Initial Scan
echo ================================================================
echo.
echo We'll scan the vulnerable test application with:
echo   - Reachability analysis
echo   - Data flow analysis (taint tracking)
echo   - ML risk prediction (using default weights)
echo.
echo Command: depguard scan --deep-analysis -v
echo.
pause

%DEPGUARD% scan --deep-analysis -v

echo.
echo [OK] Initial scan complete!
echo [INFO] Notice the ML Risk Scores and Data Flow analysis in the output
echo.
pause

echo.
echo ================================================================
echo  Step 2: Provide Feedback
echo ================================================================
echo.
echo Let's provide feedback on some vulnerabilities:
echo.
echo We'll mark vulnerabilities as:
echo   - true-positive: Actually exploitable in our code
echo   - false-positive: Not exploitable (e.g., sanitized, dev-only)
echo.
pause

echo.
echo [INFO] Marking CVE-2021-23337 (lodash template) as TRUE POSITIVE...
%DEPGUARD% feedback CVE-2021-23337 --verdict true-positive --reason "Confirmed: user input reaches lodash.template without sanitization"

echo.
echo [INFO] Marking CVE-2020-8203 (lodash merge) as FALSE POSITIVE...
%DEPGUARD% feedback CVE-2020-8203 --verdict false-positive --reason "Sanitizer prevents prototype pollution" --risk-override low

echo.
echo [INFO] Marking CVE-2021-44906 (minimist) as TRUE POSITIVE...
%DEPGUARD% feedback CVE-2021-44906 --verdict true-positive --reason "XSS in minimist, user input reaches argument parser"

echo.
echo [INFO] Marking CVE-2020-28469 (glob-parent) as FALSE POSITIVE...
%DEPGUARD% feedback CVE-2020-28469 --verdict false-positive --reason "Only used in development environment"

echo.
echo [INFO] Marking CVE-2022-25878 (protobufjs) as TRUE POSITIVE...
%DEPGUARD% feedback CVE-2022-25878 --verdict true-positive --reason "Prototype pollution in protobuf parsing"

echo.
echo [INFO] Adding more feedback entries...
%DEPGUARD% feedback CVE-2021-3807 --verdict true-positive --reason "ReDoS in async module"
%DEPGUARD% feedback CVE-2021-23368 --verdict true-positive --reason "XSS in handlebars templates"
%DEPGUARD% feedback CVE-2021-23382 --verdict false-positive --reason "Only used in test environment"
%DEPGUARD% feedback CVE-2020-7774 --verdict true-positive --reason "Prototype pollution via y18n"
%DEPGUARD% feedback CVE-2021-39134 --verdict true-positive --reason "Arbitrary code execution in @npmcli/arborist"

echo.
echo [OK] Provided feedback on 10 vulnerabilities!
echo.
pause

echo.
echo ================================================================
echo  Step 3: Check ML Status
echo ================================================================
echo.
echo Let's review our feedback statistics
echo.
echo Command: depguard ml status
echo.
pause

%DEPGUARD% ml status

echo.
echo Command: depguard ml stats
echo.
pause

%DEPGUARD% ml stats

echo.
echo [OK] We now have enough feedback to train a model!
echo.
pause

echo.
echo ================================================================
echo  Step 4: Train ML Model
echo ================================================================
echo.
echo Training a personalized ML model on your feedback...
echo.
echo The model will learn:
echo   - Which vulnerability characteristics matter in YOUR codebase
echo   - How data flow patterns correlate with exploitability
echo   - Which external indicators (EPSS, KEY) are most predictive
echo   - Code patterns that reduce risk (sanitizers, auth checks)
echo.
echo Command: depguard ml train
echo.
pause

%DEPGUARD% ml train

echo.
echo [OK] Model trained successfully!
echo [INFO] Future scans will use this personalized model
echo.
pause

echo.
echo ================================================================
echo  Step 5: Re-scan with Trained Model
echo ================================================================
echo.
echo Running another scan with the trained ML model...
echo.
echo You should see:
echo   - Risk scores adjusted based on your feedback
echo   - More accurate prioritization for YOUR specific codebase
echo   - '[ML Model: trained ✓]' indicator on findings
echo.
echo Command: depguard scan --deep-analysis -v
echo.
pause

%DEPGUARD% scan --deep-analysis -v

echo.
echo [OK] Re-scan complete with personalized risk scoring!
echo [INFO] Compare the risk scores to the initial scan
echo [INFO] Notice how CVE-2020-8203 score decreased (you marked it as false positive)
echo.
pause

echo.
echo ================================================================
echo  Step 6: Export and Analyze
echo ================================================================
echo.
echo Exporting feedback data for external analysis...
echo.
echo Command: depguard ml export feedback-data.json
echo.
pause

%DEPGUARD% ml export feedback-data.json

if exist feedback-data.json (
    echo.
    echo [OK] Feedback exported to feedback-data.json
    echo.
    echo [INFO] Preview of exported data:
    type feedback-data.json | more
)

pause

echo.
echo ================================================================
echo  Demo Complete!
echo ================================================================
echo.
echo [OK] You've successfully completed the DepGuard v2.0 demo!
echo.
echo Key Takeaways:
echo   [*] Data Flow Analysis identifies tainted vulnerabilities
echo   [*] ML Risk Prediction personalizes risk scoring to your codebase
echo   [*] Feedback loop continuously improves accuracy
echo   [*] Multi-source threat intelligence provides comprehensive coverage
echo.
echo Next Steps:
echo   1. Integrate DepGuard into your CI/CD pipeline
echo   2. Set up alerts for critical vulnerabilities
echo   3. Regularly provide feedback on new findings
echo   4. Retrain model after collecting more feedback
echo.
echo Additional Commands:
echo   - depguard scan --reachable-only      # Show only reachable vulns
echo   - depguard scan --severity critical   # Filter by severity
echo   - depguard scan -o json -f report.json # JSON output
echo   - depguard scan --disable-data-flow   # Faster scans
echo   - depguard ml status                  # Check ML status
echo   - depguard ml reset                   # Reset model
echo.
echo Documentation:
echo   - Full Demo Guide: examples\DEMO.md
echo   - Data Flow ^& ML: DATA_FLOW_AND_ML.md
echo   - Threat Intelligence: THREAT_INTELLIGENCE.md
echo   - Architecture: ARCHITECTURE.md
echo.
echo Thank you for trying DepGuard!
echo.
pause
