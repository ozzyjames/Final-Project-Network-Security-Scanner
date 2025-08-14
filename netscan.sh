#!/bin/bash

# Network Vulnerability Report Generator - Live Scanning Version with NVD API
# This script creates a dynamic report for network security scanning
# Usage: ./netscan.sh <target_ip_or_hostname>

# Global variables for timer
TIMER_PID=""
START_TIME=$(date +%s)

# Function to display progress timer
show_progress() {
    local message="$1"
    while true; do
        local current_time=$(date +%s)
        local elapsed=$((current_time - START_TIME))
        local minutes=$((elapsed / 60))
        local seconds=$((elapsed % 60))
        # Clear line, print message, and flush output
        printf "\r\033[K%s... [Running for %02d:%02d]" "$message" "$minutes" "$seconds" >&2
        sleep 10
    done
}

# Function to start progress timer
start_timer() {
    local message="$1"
    show_progress "$message" &
    TIMER_PID=$!
}

# Function to stop progress timer
stop_timer() {
    if [ -n "$TIMER_PID" ]; then
        kill $TIMER_PID 2>/dev/null
        wait $TIMER_PID 2>/dev/null
        TIMER_PID=""
        printf "\r\033[K" >&2  # Clear the entire line
    fi
}

# Cleanup function to ensure timer is stopped
cleanup() {
    stop_timer
    exit
}

# Set trap to cleanup timer on script exit
trap cleanup EXIT INT TERM

# Function to check and install required tools
check_and_install_tools() {
    echo "Checking for required tools..."
    
    # Check for nmap
    if ! command -v nmap &> /dev/null; then
        echo "nmap not found. Installing nmap..."
        
        # Detect the distribution and install accordingly
        if command -v apt &> /dev/null; then
            sudo apt update && sudo apt install -y nmap
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y nmap
        elif command -v yum &> /dev/null; then
            sudo yum install -y nmap
        elif command -v pacman &> /dev/null; then
            sudo pacman -S --noconfirm nmap
        else
            echo "Error: Cannot determine package manager. Please install nmap manually." >&2
            exit 1
        fi
        
        # Verify installation
        if ! command -v nmap &> /dev/null; then
            echo "Error: Failed to install nmap" >&2
            exit 1
        fi
        echo "nmap successfully installed!"
    else
        echo "nmap is already installed."
    fi
    
    # Check for jq
    if ! command -v jq &> /dev/null; then
        echo "jq not found. Installing jq..."
        
        if command -v apt &> /dev/null; then
            sudo apt update && sudo apt install -y jq
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y jq
        elif command -v yum &> /dev/null; then
            sudo yum install -y jq
        elif command -v pacman &> /dev/null; then
            sudo pacman -S --noconfirm jq
        else
            echo "Error: Cannot determine package manager. Please install jq manually." >&2
            exit 1
        fi
        
        # Verify installation
        if ! command -v jq &> /dev/null; then
            echo "Error: Failed to install jq" >&2
            exit 1
        fi
        echo "jq successfully installed!"
    else
        echo "jq is already installed."
    fi
    
    # Check for curl (usually pre-installed)
    if ! command -v curl &> /dev/null; then
        echo "curl not found. Installing curl..."
        
        if command -v apt &> /dev/null; then
            sudo apt update && sudo apt install -y curl
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y curl
        elif command -v yum &> /dev/null; then
            sudo yum install -y curl
        elif command -v pacman &> /dev/null; then
            sudo pacman -S --noconfirm curl
        else
            echo "Error: Cannot determine package manager. Please install curl manually." >&2
            exit 1
        fi
        
        if ! command -v curl &> /dev/null; then
            echo "Error: Failed to install curl" >&2
            exit 1
        fi
        echo "curl successfully installed!"
    else
        echo "curl is already installed."
    fi
    
    echo "All required tools are available!"
    echo ""
}

# Function to query the NVD API for vulnerabilities
query_nvd() {
    local product="$1"
    local version="$2"
    # The NVD API is public but has rate limits. We'll request a small number of results.
    local results_limit=3
    
    echo # Add a newline for formatting
    echo "Querying NVD for vulnerabilities in: $product $version..."

    # The API needs a URL-encoded string. A simple space-to-%20 works for many cases.
    local search_query
    search_query=$(echo "$product $version" | sed 's/ /%20/g')

    local nvd_api_url="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${search_query}&resultsPerPage=${results_limit}"

    # Use curl to fetch the data (-s for silent) and jq to parse the JSON response.
    # We pipe the output of curl directly into jq.
    local vulnerabilities_json
    vulnerabilities_json=$(curl -s "$nvd_api_url")

    # --- Defensive Programming: Check for Errors ---
    if [[ -z "$vulnerabilities_json" ]]; then
        echo "  [!] Error: Failed to fetch data from NVD. The API might be down or unreachable."
        return
    fi
    if echo "$vulnerabilities_json" | jq -e '.message' > /dev/null; then
        echo "  [!] NVD API Error: $(echo "$vulnerabilities_json" | jq -r '.message')"
        return
    fi
    if ! echo "$vulnerabilities_json" | jq -e '.vulnerabilities[0]' > /dev/null; then
        echo "  [+] No vulnerabilities found in NVD for this keyword search."
        return
    fi
    # --- End Error Checks ---

    # This jq command filters the JSON and formats it for our report.
    # It extracts the CVE ID, the English description, and the severity.
    echo "$vulnerabilities_json" | jq -r \
        '.vulnerabilities[] |
        "  CVE ID: \(.cve.id)\n  Description: \((.cve.descriptions[] | select(.lang=="en")).value | gsub("\n"; " "))\n  Severity: \(.cve.metrics.cvssMetricV31[0].cvssData.baseSeverity // .cve.metrics.cvssMetricV2[0].cvssData.baseSeverity // "N/A")\n---"'
}

# Function to write the report header section
# Takes target IP/hostname as parameter
write_header() {
    local target="$1"
    echo "=========================================="
    echo "     NETWORK SECURITY SCAN REPORT"
    echo "=========================================="
    echo ""
    echo "Generated on: $(date)"
    echo "Scan performed by: Network Security Scanner v2.0 (NVD Enhanced)"
    echo ""
    echo "=========================================="
    echo "TARGET INFORMATION"
    echo "=========================================="
    echo "Target IP Address/Hostname: $target"
    echo "Scan Type: Comprehensive Vulnerability Assessment with NVD Integration"
    echo "Scan Duration: (Will be created by actual scan)"
    echo ""
}

# Function to write the ports and services section - NOW WITH LIVE SCANNING
write_ports_section() {
    local target="$1"
    
    # Display progress to terminal (not to file)
    start_timer "Scanning ports and services"
    
    echo "=========================================="
    echo "OPEN PORTS AND DETECTED SERVICES"
    echo "=========================================="
    echo ""
    echo "The following ports were found to be open:"
    echo ""
    
    # Execute live nmap scan and filter for open ports
    sudo nmap -sV "$target" | grep "open"
    
    # Stop timer (display to terminal)
    stop_timer
    
    echo ""
}

# Function to write the vulnerabilities section - ENHANCED WITH NSE, VERSION CHECKING, AND NVD API
write_vulns_section() {
    local target="$1"
    local REPORT_FILE="$2"
    
    echo "=========================================="
    echo "POTENTIAL VULNERABILITIES IDENTIFIED"
    echo "=========================================="
    echo ""
    
    # Start timer for vulnerability scanning (display to terminal)
    start_timer "Performing comprehensive vulnerability scan"
    
    # Capture full scan results with vulnerability scripts (suppress output during scan)
    local SCAN_RESULTS=$(sudo nmap -sV --script vuln "$target" 2>/dev/null)
    
    # Stop the scanning timer (display to terminal)
    stop_timer
    
    echo "Performing comprehensive vulnerability scan... Complete!"
    echo ""
    echo "--- NSE Vulnerability Scan Results ---"
    echo ""
    
    # Strategy A: Grep for High-Confidence NSE Results
    local nse_vulns=$(echo "$SCAN_RESULTS" | grep "VULNERABLE")
    if [ -n "$nse_vulns" ]; then
        echo "NSE Script Detected Vulnerabilities:"
        echo "$nse_vulns"
        echo ""
    else
        echo "No direct VULNERABLE flags found in NSE scan results."
        echo ""
    fi
    
    # Strategy B: Use Conditional Logic for Version Checking with NVD Integration
    echo "--- Analyzing Service Versions with NVD Integration ---"
    echo ""
    
    # Start timer for NVD queries (display to terminal)
    start_timer "Querying NVD database for vulnerability information"
    
    # Process the full scan results line by line
    echo "$SCAN_RESULTS" | while read -r line; do
        local product_name=""
        local product_version=""
        
        # Use a case statement to check for specific vulnerable versions and extract service info
        case "$line" in
            *"vsftpd 2.3.4"*)
                echo "[!!] VULNERABILITY DETECTED: vsftpd 2.3.4 is running, which contains a known critical backdoor."
                product_name="vsftpd"
                product_version="2.3.4"
                ;;
            *"Apache httpd"*)
                if [[ "$line" =~ Apache\ httpd\ ([0-9]+\.[0-9]+\.[0-9]+) ]]; then
                    product_version="${BASH_REMATCH[1]}"
                    product_name="Apache httpd"
                    echo "[!!] VULNERABILITY DETECTED: Apache $product_version is running, checking NVD for known vulnerabilities."
                fi
                ;;
            *"OpenSSH"*)
                if [[ "$line" =~ OpenSSH\ ([0-9]+\.[0-9]+) ]]; then
                    product_version="${BASH_REMATCH[1]}"
                    product_name="OpenSSH"
                    echo "[!!] VULNERABILITY DETECTED: OpenSSH $product_version is running, checking NVD for known vulnerabilities."
                fi
                ;;
            *"nginx"*)
                if [[ "$line" =~ nginx\ ([0-9]+\.[0-9]+) ]]; then
                    product_version="${BASH_REMATCH[1]}"
                    product_name="nginx"
                    echo "[!!] VULNERABILITY DETECTED: nginx $product_version is running, checking NVD for known vulnerabilities."
                fi
                ;;
            *"MySQL"*)
                if [[ "$line" =~ MySQL\ ([0-9]+\.[0-9]+) ]]; then
                    product_version="${BASH_REMATCH[1]}"
                    product_name="MySQL"
                    echo "[!!] VULNERABILITY DETECTED: MySQL $product_version is running, checking NVD for known vulnerabilities."
                fi
                ;;
        esac
        
        # If we extracted product info, query NVD (but limit to avoid rate limiting during testing)
        if [[ -n "$product_name" && -n "$product_version" ]]; then
            # Only query first two services found to avoid rate limiting during testing
            local service_count=$(grep -c "Querying NVD" "$REPORT_FILE" 2>/dev/null || echo "0")
            if [[ $service_count -lt 2 ]]; then
                query_nvd "$product_name" "$product_version" >> "$REPORT_FILE"
                # Add a small delay to be respectful to the API
                sleep 1
            else
                echo "  [Note] Additional services found but limiting NVD queries to avoid rate limiting during testing."
            fi
        fi
    done
    
    # Stop the NVD timer (display to terminal)
    stop_timer
    
    echo "NVD database queries... Complete!"
    echo ""
    echo "--- Additional Vulnerability Checks ---"
    echo ""
    
    # Check for additional vulnerability indicators in scan results
    if echo "$SCAN_RESULTS" | grep -q "CVE-"; then
        echo "CVE References found in scan:"
        echo "$SCAN_RESULTS" | grep "CVE-" | head -5
        echo ""
    fi
    
    # Check for common vulnerability keywords
    if echo "$SCAN_RESULTS" | grep -qi "exploit\|backdoor\|weak\|insecure"; then
        echo "Potential security issues detected:"
        echo "$SCAN_RESULTS" | grep -i "exploit\|backdoor\|weak\|insecure" | head -3
        echo ""
    fi
    
    echo "Vulnerability scan completed. Review results above for security issues."
    echo ""
}

# Function to write the recommendations section
write_recs_section() {
    echo "=========================================="
    echo "RECOMMENDATIONS FOR REMEDIATION"
    echo "=========================================="
    echo ""
    echo "Immediate Actions Required (High Priority):"
    echo "  1. Address all CVEs identified by NVD API queries immediately"
    echo "  2. Update Apache web server to the latest stable version"
    echo "  3. Change default database credentials immediately"
    echo "  4. Implement strong password policies for all services"
    echo "  5. Address any NSE-detected vulnerabilities immediately"
    echo ""
    echo "Short-term Improvements (Medium Priority):"
    echo "  6. Configure SSH to use only strong encryption ciphers"
    echo "  7. Disable server version disclosure in HTTP headers"
    echo "  8. Implement proper firewall rules to restrict access"
    echo "  9. Update all services to their latest secure versions"
    echo "  10. Monitor NVD regularly for new vulnerabilities affecting your services"
    echo ""
    echo "Long-term Security Enhancements:"
    echo "  11. Establish regular vulnerability scanning schedule with NVD integration"
    echo "  12. Implement intrusion detection system (IDS)"
    echo "  13. Set up log monitoring and alerting"
    echo "  14. Conduct regular security awareness training"
    echo "  15. Implement automated vulnerability management system"
    echo ""
}

# Function to write the footer section
write_footer() {
    echo "=========================================="
    echo "SCAN SUMMARY"
    echo "=========================================="
    echo ""
    echo "Ports Scanned: [Populated by nmap scan results]"
    echo "Services Identified: [Based on live scan results]"
    echo "Vulnerabilities Found: [Based on NSE, version analysis, and NVD API]"
    echo "NVD Integration: Active (Limited queries during testing)"
    echo "Overall Risk Level: [Determined by vulnerability severity and CVE data]"
    echo ""
    echo "Next Recommended Action: Address high-risk CVEs and vulnerabilities immediately"
    echo ""
    echo "=========================================="
    echo "END OF REPORT"
    echo "=========================================="
    echo ""
    echo "Report generated on: $(date)"
    echo "NVD API Integration: Enabled"
    echo "For questions about this report, contact: security@company.com"
    echo ""
}

# Main function that orchestrates the entire script execution
main() {
    # Input validation - check if exactly one argument is provided
    if [ $# -ne 1 ]; then
        echo "Usage: $0 <target_ip_or_hostname>" >&2
        exit 1
    fi
    
    # Check and install required tools first
    check_and_install_tools
    
    # Store the target from command line argument
    local target="$1"
    
    # Define output filename
    local REPORT_FILE="network_security_report.txt"
    
    echo "Starting comprehensive vulnerability scan of $target..."
    echo "This may take several minutes due to NSE vulnerability scripts and NVD API queries..."
    echo "Progress will be displayed every 10 seconds..."
    echo ""
    
    # Generate the report by calling each function in sequence
    echo "Phase 1/4: Generating report header..."
    write_header "$target" > "$REPORT_FILE"
    
    echo "Phase 2/4: Scanning ports and services..."
    write_ports_section "$target" >> "$REPORT_FILE"
    
    echo "Phase 3/4: Analyzing vulnerabilities and querying NVD..."
    write_vulns_section "$target" "$REPORT_FILE" >> "$REPORT_FILE"
    
    echo "Phase 4/4: Adding recommendations and finalizing report..."
    write_recs_section >> "$REPORT_FILE"
    write_footer >> "$REPORT_FILE"
    
    # Confirm successful creation and show preview
    if [ -f "$REPORT_FILE" ]; then
        echo "Network security report successfully generated: $REPORT_FILE"
        echo "Target scanned: $target"
        echo "Report contains $(wc -l < "$REPORT_FILE") lines"
        echo ""
        echo "Preview of the report:"
        echo "====================="
        head -15 "$REPORT_FILE"
        echo "..."
        echo "(Full report saved to $REPORT_FILE)"
        echo ""
        echo "Note: NVD API queries were limited to first 2 services to avoid rate limiting during testing."
        echo "Remove the service_count limitation in production use."
    else
        echo "Error: Failed to create report file" >&2
        exit 1
    fi
}

# Script execution starts here - call main function with all arguments
main "$@"
