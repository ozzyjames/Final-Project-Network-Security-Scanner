#!/bin/bash

# Network Vulnerability Report Generator - Live Scanning Version
# This script creates a dynamic report for network security scanning
# Usage: ./netscan.sh <target_ip_or_hostname>

# Function to write the report header section
# Takes target IP/hostname as parameter
write_header() {
    local target="$1"
    echo "=========================================="
    echo "     NETWORK SECURITY SCAN REPORT"
    echo "=========================================="
    echo ""
    echo "Generated on: $(date)"
    echo "Scan performed by: Network Security Scanner v1.0"
    echo ""
    echo "=========================================="
    echo "TARGET INFORMATION"
    echo "=========================================="
    echo "Target IP Address/Hostname: $target"
    echo "Scan Type: Comprehensive Vulnerability Assessment"
    echo "Scan Duration: (Will be created by actual scan)"
    echo ""
}

# Function to write the ports and services section - NOW WITH LIVE SCANNING
write_ports_section() {
    local target="$1"
    echo "=========================================="
    echo "OPEN PORTS AND DETECTED SERVICES"
    echo "=========================================="
    echo ""
    echo "The following ports were found to be open:"
    echo ""
    
    # Execute live nmap scan and filter for open ports
    nmap -sV "$target" | grep "open"
    
    echo ""
}

# Function to write the vulnerabilities section - ENHANCED WITH NSE AND VERSION CHECKING
write_vulns_section() {
    local target="$1"
    echo "=========================================="
    echo "POTENTIAL VULNERABILITIES IDENTIFIED"
    echo "=========================================="
    echo ""
    
    # Capture full scan results with vulnerability scripts
    echo "Performing comprehensive vulnerability scan..."
    local SCAN_RESULTS=$(nmap -sV --script vuln "$target" 2>/dev/null)
    
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
    
    # Strategy B: Use Conditional Logic for Version Checking
    echo "--- Analyzing Service Versions ---"
    echo ""
    
    # Process the full scan results line by line
    echo "$SCAN_RESULTS" | while read -r line; do
        # Use a case statement to check for specific vulnerable versions
        case "$line" in
            *"vsftpd 2.3.4"*)
                echo "[!!] VULNERABILITY DETECTED: vsftpd 2.3.4 is running, which contains a known critical backdoor."
                ;;
            *"Apache httpd 2.4.49"*)
                echo "[!!] VULNERABILITY DETECTED: Apache 2.4.49 is running, which is vulnerable to path traversal (CVE-2021-41773)."
                ;;
            *"OpenSSH 7.4"*)
                echo "[!!] VULNERABILITY DETECTED: OpenSSH 7.4 is running, which is vulnerable to user enumeration (CVE-2018-15473)."
                ;;
            *"nginx 1.10"*)
                echo "[!!] VULNERABILITY DETECTED: nginx 1.10.x is running, which has known vulnerabilities including integer overflow (CVE-2017-7529)."
                ;;
            *"MySQL 5.5"*)
                echo "[!!] VULNERABILITY DETECTED: MySQL 5.5.x is running, which has multiple known vulnerabilities including privilege escalation issues."
                ;;
        esac
    done
    
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
    echo "  1. Update Apache web server to the latest stable version"
    echo "  2. Change default database credentials immediately"
    echo "  3. Implement strong password policies for all services"
    echo "  4. Address any NSE-detected vulnerabilities immediately"
    echo ""
    echo "Short-term Improvements (Medium Priority):"
    echo "  5. Configure SSH to use only strong encryption ciphers"
    echo "  6. Disable server version disclosure in HTTP headers"
    echo "  7. Implement proper firewall rules to restrict access"
    echo "  8. Update all services to their latest secure versions"
    echo ""
    echo "Long-term Security Enhancements:"
    echo "  9. Establish regular vulnerability scanning schedule"
    echo "  10. Implement intrusion detection system (IDS)"
    echo "  11. Set up log monitoring and alerting"
    echo "  12. Conduct regular security awareness training"
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
    echo "Vulnerabilities Found: [Based on NSE and version analysis]"
    echo "Overall Risk Level: [Determined by vulnerability severity]"
    echo ""
    echo "Next Recommended Action: Address high-risk vulnerabilities immediately"
    echo ""
    echo "=========================================="
    echo "END OF REPORT"
    echo "=========================================="
    echo ""
    echo "Report generated on: $(date)"
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
    
    # Store the target from command line argument
    local target="$1"
    
    # Define output filename
    local REPORT_FILE="network_security_report.txt"
    
    echo "Starting comprehensive vulnerability scan of $target..."
    echo "This may take several minutes due to NSE vulnerability scripts..."
    echo ""
    
    # Generate the report by calling each function in sequence
    write_header "$target" > "$REPORT_FILE"
    
    write_ports_section "$target" >> "$REPORT_FILE"
    write_vulns_section "$target" >> "$REPORT_FILE"
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
        head -10 "$REPORT_FILE"
        echo "..."
        echo "(Full report saved to $REPORT_FILE)"
    else
        echo "Error: Failed to create report file" >&2
        exit 1
    fi
}

# Script execution starts here - call main function with all arguments
main "$@"
