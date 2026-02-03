# DepGuard Scanner for C:\Users\cczin\dependency-bad
# PowerShell script to scan all services

$depguardPath = "C:\Users\cczin\appservice-scan"
$targetPath = "C:\Users\cczin\dependency-bad"
$reportsDir = "$depguardPath\reports"

# Create reports directory if it doesn't exist
if (-not (Test-Path $reportsDir)) {
    New-Item -ItemType Directory -Path $reportsDir | Out-Null
}

Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║        DepGuard Multi-Service Scanner                         ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Scan Next.js Frontend
Write-Host "📦 Scanning Next.js Frontend..." -ForegroundColor Yellow
Set-Location $depguardPath
node bin\depguard.js scan --path "$targetPath\nextjs-frontend" --reachable-only --output html --file "$reportsDir\nextjs-report.html"
Write-Host "✓ Next.js scan complete" -ForegroundColor Green
Write-Host ""

# Scan Python Service
Write-Host "🐍 Scanning Python Service..." -ForegroundColor Yellow
node bin\depguard.js scan --path "$targetPath\python-service" --reachable-only --output html --file "$reportsDir\python-report.html"
Write-Host "✓ Python scan complete" -ForegroundColor Green
Write-Host ""

# Scan Java Backend
Write-Host "☕ Scanning Java Backend..." -ForegroundColor Yellow
node bin\depguard.js scan --path "$targetPath\java-backend" --reachable-only --output html --file "$reportsDir\java-report.html"
Write-Host "✓ Java scan complete" -ForegroundColor Green
Write-Host ""

# Summary
Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                  Scan Complete!                                ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "Reports saved to: $reportsDir" -ForegroundColor Green
Write-Host ""
Write-Host "View reports:" -ForegroundColor Yellow
Write-Host "  - Next.js: $reportsDir\nextjs-report.html" -ForegroundColor White
Write-Host "  - Python:  $reportsDir\python-report.html" -ForegroundColor White
Write-Host "  - Java:    $reportsDir\java-report.html" -ForegroundColor White
Write-Host ""

# Open reports folder
$openReports = Read-Host "Open reports folder? (Y/n)"
if ($openReports -ne "n") {
    Start-Process $reportsDir
}
