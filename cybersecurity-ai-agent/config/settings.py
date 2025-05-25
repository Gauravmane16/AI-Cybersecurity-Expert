import os
from typing import Dict, List

class SecurityDomains:
    NETWORK_SECURITY = "Network Security"
    APPLICATION_SECURITY = "Application Security"
    CLOUD_SECURITY = "Cloud Security"
    ENDPOINT_PROTECTION = "Endpoint Protection"
    MALWARE_ANALYSIS = "Malware Analysis"
    PENETRATION_TESTING = "Penetration Testing"
    THREAT_DETECTION = "Threat Detection & Mitigation"
    SECURE_CODING = "Secure Coding Practices"
    DEVSECOPS = "DevSecOps Integration"
    COMPLIANCE = "Compliance & Regulatory"

SECURITY_DOMAINS = [
    SecurityDomains.NETWORK_SECURITY,
    SecurityDomains.APPLICATION_SECURITY,
    SecurityDomains.CLOUD_SECURITY,
    SecurityDomains.ENDPOINT_PROTECTION,
    SecurityDomains.MALWARE_ANALYSIS,
    SecurityDomains.PENETRATION_TESTING,
    SecurityDomains.THREAT_DETECTION,
    SecurityDomains.SECURE_CODING,
    SecurityDomains.DEVSECOPS,
    SecurityDomains.COMPLIANCE
]

SECURITY_TOOLS = {
    SecurityDomains.NETWORK_SECURITY: ["Wireshark", "Nmap", "Netcat", "TCPDump", "Nessus"],
    SecurityDomains.APPLICATION_SECURITY: ["OWASP ZAP", "Burp Suite", "SQLMap", "Nikto", "W3AF"],
    SecurityDomains.CLOUD_SECURITY: ["CloudMapper", "Scout Suite", "Prowler", "CloudSploit"],
    SecurityDomains.ENDPOINT_PROTECTION: ["YARA", "Volatility", "Sysinternals", "OSQuery"],
    SecurityDomains.MALWARE_ANALYSIS: ["Ghidra", "IDA Pro", "Radare2", "Cuckoo Sandbox"],
    SecurityDomains.PENETRATION_TESTING: ["Metasploit", "Cobalt Strike", "Empire", "BeEF"],
    SecurityDomains.THREAT_DETECTION: ["SIEM Tools", "Snort", "Suricata", "ELK Stack"],
    SecurityDomains.SECURE_CODING: ["SonarQube", "Checkmarx", "Veracode", "SAST Tools"],
    SecurityDomains.DEVSECOPS: ["Jenkins", "GitLab CI", "Docker Security", "Kubernetes Security"],
    SecurityDomains.COMPLIANCE: ["Nessus", "OpenSCAP", "Compliance Scanners"]
}