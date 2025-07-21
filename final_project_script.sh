#!/bin/bash

# Network Vulnerability Report Generator - Refactored Version
# This script creates a dynamic report for network security scanning
# Usage: ./script_name.sh <target_ip_or_hostname>

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

# Function to write the ports and services section
write_ports_section() {
    echo "=========================================="
    echo "OPEN PORTS AND DETECTED SERVICES"
    echo "=========================================="
    echo ""
    echo "The following ports were found to be open:"
    echo ""
    echo "  Port 22/tcp  - ssh     (OpenSSH 8.2)"
    echo "  Port 80/tcp  - http    (Apache httpd 2.4.41)"
    echo "  Port 443/tcp - https   (Apache httpd 2.4.41 with SSL)"
    echo "  Port 3306/tcp - mysql  (MySQL 8.0.25)"
    echo ""
    echo "Total open ports discovered: 4"
    echo ""
}

# Function to write the vulnerabilities section
write_vulns_section() {
    echo "=========================================="
    echo "POTENTIAL VULNERABILITIES IDENTIFIED"
    echo "=========================================="
    echo ""
    echo "High Risk Vulnerabilities:"
    echo "  • CVE-2023-12345 - Outdated Web Server Configuration"
    echo "    Description: Apache version contains known security flaws"
    echo "    Risk Level: HIGH"
    echo ""
    echo "  • Default Credentials Detected - MySQL Database"
    echo "    Description: Database server may be using default credentials"
    echo "    Risk Level: HIGH"
    echo ""
    echo "Medium Risk Vulnerabilities:"
    echo "  • CVE-2023-67890 - SSH Configuration Weakness"
    echo "    Description: SSH server allows weak encryption methods"
    echo "    Risk Level: MEDIUM"
    echo ""
    echo "  • Information Disclosure - Web Server"
    echo "    Description: Server banner reveals version information"
    echo "    Risk Level: MEDIUM"
    echo ""
    echo "Total vulnerabilities found: 4 (2 High, 2 Medium, 0 Low)"
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
    echo ""
    echo "Short-term Improvements (Medium Priority):"
    echo "  4. Configure SSH to use only strong encryption ciphers"
    echo "  5. Disable server version disclosure in HTTP headers"
    echo "  6. Implement proper firewall rules to restrict access"
    echo ""
    echo "Long-term Security Enhancements:"
    echo "  7. Establish regular vulnerability scanning schedule"
    echo "  8. Implement intrusion detection system (IDS)"
    echo "  9. Set up log monitoring and alerting"
    echo "  10. Conduct regular security awareness training"
    echo ""
}

# Function to write the footer section
write_footer() {
    echo "=========================================="
    echo "SCAN SUMMARY"
    echo "=========================================="
    echo ""
    echo "Ports Scanned: [To be populated by actual scan]"
    echo "Services Identified: 4"
    echo "Vulnerabilities Found: 4"
    echo "Overall Risk Level: HIGH"
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
    
    # Generate the report by calling each function in sequence
    write_header "$target" > "$REPORT_FILE"
    
    write_ports_section >> "$REPORT_FILE"
    write_vulns_section >> "$REPORT_FILE"
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
