# Final-Project-Network-Security-Scanner
A comprehensive bash script that performs live network scanning and generates detailed security reports for target hosts.
Overview
This tool creates dynamic vulnerability assessment reports by performing real-time network scans using nmap and combining the results with predefined vulnerability analysis. The script generates professional, formatted reports suitable for security audits and compliance documentation.
Features

Live Network Scanning: Performs real-time port and service detection using nmap
Automated Report Generation: Creates structured, professional security reports
Comprehensive Analysis: Includes vulnerability identification and risk assessment
Actionable Recommendations: Provides prioritized remediation steps
Easy Integration: Simple command-line interface for automation workflows

Requirements
System Dependencies

Bash shell (version 4.0 or higher)
nmap - Network exploration tool and security scanner
Standard Unix utilities: date, wc, head, grep

Installation of Dependencies
Ubuntu/Debian:
bashsudo apt update
sudo apt install nmap
CentOS/RHEL/Fedora:
bashsudo yum install nmap  # CentOS/RHEL
sudo dnf install nmap  # Fedora
macOS:
bashbrew install nmap
Installation

Download the script:
bashwget https://github.com/ozzyjames/Final-Project-Network-Security-Scanner.sh
# or
curl -O https://github.com/ozzyjames/Final-Project-Network-Security-Scanner.sh

Make it executable:
bashchmod +x final_project_script.sh

Optionally, move to PATH for system-wide access:
bashsudo mv final_project_script.sh /usr/local/bin/netscan


Usage
Basic Syntax
bash./final_project_script.sh <target_ip_or_hostname>
Examples
Scan a local machine:
bash./final_project_script.sh 127.0.0.1
Scan a remote server:
bash./final_project_script.sh example.com
Scan an IP address:
bash./final_project_script.sh 192.168.1.100
Output
The script generates a file named network_security_report.txt containing:

Target information and scan metadata
Live port scan results from nmap
Identified vulnerabilities with risk levels
Prioritized remediation recommendations
Executive summary

Report Structure
The generated report includes the following sections:

Header Information

Timestamp and scanner version
Target details and scan type


Open Ports and Services

Real-time nmap scan results
Service version detection


Vulnerability Analysis

High, medium, and low risk vulnerabilities
CVE references where applicable
Risk level assessments


Remediation Recommendations

Immediate actions (high priority)
Short-term improvements (medium priority)
Long-term security enhancements


Scan Summary

Statistics and overall risk assessment
Next steps and contact information



Security Considerations
Ethical Use

Only scan networks you own or have explicit permission to test
Unauthorized network scanning may violate local laws and regulations
Always obtain written authorization before scanning third-party systems

Permissions

The script may require elevated privileges for certain scan types
Consider running with appropriate user permissions for your environment

Rate Limiting

The script performs standard nmap scans which are generally non-intrusive
For production environments, consider implementing scan timing controls

Customization
Modifying Vulnerability Database
Edit the write_vulns_section() function to include organization-specific vulnerabilities:
bashwrite_vulns_section() {
    echo "Your custom vulnerability checks here"
    # Add your specific CVEs and security checks
}
Custom Scan Parameters
Modify the nmap command in write_ports_section() for different scan types:
bash# Example: Stealth SYN scan with OS detection
nmap -sS -O "$target" | grep "open"

# Example: UDP scan
nmap -sU "$target" | grep "open"
Report Formatting
Customize the report appearance by modifying the echo statements in each function.
Troubleshooting
Common Issues
"nmap: command not found"

Install nmap using your system's package manager (see Requirements section)

Permission denied errors

Ensure the script has execute permissions: chmod +x final_project_script.sh
Some scans may require sudo privileges

Empty port scan results

Verify the target is reachable: ping <target>
Check firewall settings that might block nmap
Ensure target host is responsive

Report file not created

Check write permissions in the current directory
Verify sufficient disk space
Review any error messages displayed

Debug Mode
For troubleshooting, run the script with bash debug mode:
bashbash -x final_project_script.sh <target>
Contributing

Fork the repository
Create a feature branch (git checkout -b feature/new-feature)
Commit your changes (git commit -am 'Add new feature')
Push to the branch (git push origin feature/new-feature)
Create a Pull Request

Initial release with basic network scanning functionality
Live nmap integration
Comprehensive report generation
Vulnerability assessment framework


Disclaimer
This tool is intended for authorized security testing and educational purposes only. Users are responsible for ensuring compliance with applicable laws and regulations. The authors assume no liability for misuse of this software.
