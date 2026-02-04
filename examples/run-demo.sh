#!/bin/bash

# DepGuard v2.0 Interactive Demo Script
# This script walks you through the complete workflow

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Demo directory
DEMO_DIR="$(cd "$(dirname "$0")" && pwd)/vulnerable-test-app"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DEPGUARD="node $ROOT_DIR/bin/depguard.js"

echo -e "${CYAN}${BOLD}"
echo "================================================================"
echo ""
echo "             DepGuard v2.0 Interactive Demo"
echo ""
echo "  Data Flow Analysis + Machine Learning Risk Prediction"
echo ""
echo "================================================================"
echo -e "${NC}"

pause() {
    echo ""
    echo -e "${YELLOW}Press Enter to continue...${NC}"
    read -r
    echo ""
}

step() {
    echo ""
    echo -e "${CYAN}${BOLD}================================================================${NC}"
    echo -e "${CYAN}${BOLD} $1${NC}"
    echo -e "${CYAN}${BOLD}================================================================${NC}"
    echo ""
}

success() {
    echo -e "${GREEN}[OK] $1${NC}"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

# Check if demo app exists
if [ ! -d "$DEMO_DIR" ]; then
    echo -e "${RED}Error: Demo app not found at $DEMO_DIR${NC}"
    echo "Please run from the examples directory"
    exit 1
fi

cd "$DEMO_DIR"

# Clean up previous runs
rm -rf .depguard-cache .depguard-feedback .depguard-models 2>/dev/null || true

step "Step 1: Initial Scan"
info "We'll scan the vulnerable test application with:"
echo "  • Reachability analysis"
echo "  • Data flow analysis (taint tracking)"
echo "  • ML risk prediction (using default weights)"
echo ""
info "Command: depguard scan --deep-analysis -v"
pause

$DEPGUARD scan --deep-analysis -v

success "Initial scan complete!"
info "Notice the ML Risk Scores and Data Flow analysis in the output"
pause

step "Step 2: Provide Feedback"
info "Let's provide feedback on some vulnerabilities:"
echo ""
echo "We'll mark vulnerabilities as:"
echo "  • true-positive: Actually exploitable in our code"
echo "  • false-positive: Not exploitable (e.g., sanitized, dev-only)"
pause

echo ""
info "Marking CVE-2021-23337 (lodash template) as TRUE POSITIVE..."
$DEPGUARD feedback CVE-2021-23337 \
  --verdict true-positive \
  --reason "Confirmed: user input reaches lodash.template without sanitization" || true

echo ""
info "Marking CVE-2020-8203 (lodash merge) as FALSE POSITIVE..."
$DEPGUARD feedback CVE-2020-8203 \
  --verdict false-positive \
  --reason "Sanitizer prevents prototype pollution" \
  --risk-override low || true

echo ""
info "Marking CVE-2021-44906 (minimist) as TRUE POSITIVE..."
$DEPGUARD feedback CVE-2021-44906 \
  --verdict true-positive \
  --reason "XSS in minimist, user input reaches argument parser" || true

echo ""
info "Marking CVE-2020-28469 (glob-parent) as FALSE POSITIVE..."
$DEPGUARD feedback CVE-2020-28469 \
  --verdict false-positive \
  --reason "Only used in development environment" || true

echo ""
info "Marking CVE-2022-25878 (protobufjs) as TRUE POSITIVE..."
$DEPGUARD feedback CVE-2022-25878 \
  --verdict true-positive \
  --reason "Prototype pollution in protobuf parsing" || true

echo ""
info "Adding more feedback entries..."
$DEPGUARD feedback CVE-2021-3807 \
  --verdict true-positive \
  --reason "ReDoS in async module" || true

$DEPGUARD feedback CVE-2021-23368 \
  --verdict true-positive \
  --reason "XSS in handlebars templates" || true

$DEPGUARD feedback CVE-2021-23382 \
  --verdict false-positive \
  --reason "Only used in test environment" || true

$DEPGUARD feedback CVE-2020-7774 \
  --verdict true-positive \
  --reason "Prototype pollution via y18n" || true

$DEPGUARD feedback CVE-2021-39134 \
  --verdict true-positive \
  --reason "Arbitrary code execution in @npmcli/arborist" || true

success "Provided feedback on 10 vulnerabilities!"
pause

step "Step 3: Check ML Status"
info "Let's review our feedback statistics"
echo ""
info "Command: depguard ml status"
pause

$DEPGUARD ml status

echo ""
info "Command: depguard ml stats"
pause

$DEPGUARD ml stats

success "We now have enough feedback to train a model!"
pause

step "Step 4: Train ML Model"
info "Training a personalized ML model on your feedback..."
echo ""
info "The model will learn:"
echo "  • Which vulnerability characteristics matter in YOUR codebase"
echo "  • How data flow patterns correlate with exploitability"
echo "  • Which external indicators (EPSS, KEV) are most predictive"
echo "  • Code patterns that reduce risk (sanitizers, auth checks)"
echo ""
info "Command: depguard ml train"
pause

$DEPGUARD ml train

success "Model trained successfully!"
info "Future scans will use this personalized model"
pause

step "Step 5: Re-scan with Trained Model"
info "Running another scan with the trained ML model..."
echo ""
info "You should see:"
echo "  • Risk scores adjusted based on your feedback"
echo "  • More accurate prioritization for YOUR specific codebase"
echo "  • '[ML Model: trained ✓]' indicator on findings"
echo ""
info "Command: depguard scan --deep-analysis -v"
pause

$DEPGUARD scan --deep-analysis -v

success "Re-scan complete with personalized risk scoring!"
info "Compare the risk scores to the initial scan"
info "Notice how CVE-2020-8203 score decreased (you marked it as false positive)"
pause

step "Step 6: Export and Analyze"
info "Exporting feedback data for external analysis..."
echo ""
info "Command: depguard ml export feedback-data.json"
pause

$DEPGUARD ml export feedback-data.json

if [ -f "feedback-data.json" ]; then
    success "Feedback exported to feedback-data.json"
    echo ""
    info "Preview of exported data:"
    head -n 20 feedback-data.json
    echo "..."
fi

pause

step "Demo Complete!"
echo ""
success "You've successfully completed the DepGuard v2.0 demo!"
echo ""
info "Key Takeaways:"
echo "  [*] Data Flow Analysis identifies tainted vulnerabilities"
echo "  [*] ML Risk Prediction personalizes risk scoring to your codebase"
echo "  [*] Feedback loop continuously improves accuracy"
echo "  [*] Multi-source threat intelligence provides comprehensive coverage"
echo ""
info "Next Steps:"
echo "  1. Integrate DepGuard into your CI/CD pipeline"
echo "  2. Set up alerts for critical vulnerabilities"
echo "  3. Regularly provide feedback on new findings"
echo "  4. Retrain model after collecting more feedback"
echo ""
info "Additional Commands:"
echo "  - depguard scan --reachable-only      # Show only reachable vulns"
echo "  - depguard scan --severity critical   # Filter by severity"
echo "  - depguard scan -o json -f report.json # JSON output"
echo "  - depguard scan --disable-data-flow   # Faster scans"
echo "  - depguard ml status                  # Check ML status"
echo "  - depguard ml reset                   # Reset model"
echo ""
info "Documentation:"
echo "  - Full Demo Guide: examples/DEMO.md"
echo "  - Data Flow & ML: DATA_FLOW_AND_ML.md"
echo "  - Threat Intelligence: THREAT_INTELLIGENCE.md"
echo "  - Architecture: ARCHITECTURE.md"
echo ""
echo -e "${GREEN}${BOLD}Thank you for trying DepGuard!${NC}"
echo ""
