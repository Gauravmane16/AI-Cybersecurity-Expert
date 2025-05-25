class SecurityCodeGenerator:
    def __init__(self):
        self.code_templates = self._initialize_templates()
    
    def _initialize_templates(self) -> dict:
        return {
            'nmap_scan': '''# Nmap Network Scan
import subprocess
import json

def nmap_scan(target, scan_type="basic"):
    """
    Perform Nmap scan on target
    Args:
        target (str): IP address or hostname
        scan_type (str): Type of scan (basic, stealth, service)
    """
    scan_commands = {
        "basic": f"nmap -sn {target}",
        "stealth": f"nmap -sS -T2 {target}",
        "service": f"nmap -sV -sC {target}",
        "vulnerability": f"nmap --script vuln {target}"
    }
    
    try:
        result = subprocess.run(
            scan_commands.get(scan_type, scan_commands["basic"]).split(),
            capture_output=True,
            text=True,
            timeout=300
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return "Scan timed out"
    except Exception as e:
        return f"Error: {str(e)}"

# Example usage
if __name__ == "__main__":
    target_ip = "192.168.1.1"
    result = nmap_scan(target_ip, "service")
    print(result)''',

            'sql_injection_test': '''# SQL Injection Testing Script
import requests
import urllib.parse

def test_sql_injection(url, parameter, payloads=None):
    """
    Test for SQL injection vulnerabilities
    Args:
        url (str): Target URL
        parameter (str): Parameter to test
        payloads (list): SQL injection payloads
    """
    if payloads is None:
        payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' OR 1=1#",
            "admin'--"
        ]
    
    vulnerable = []
    
    for payload in payloads:
        encoded_payload = urllib.parse.quote(payload)
        test_url = f"{url}?{parameter}={encoded_payload}"
        
        try:
            response = requests.get(test_url, timeout=10)
            
            # Check for SQL error indicators
            error_indicators = [
                "sql syntax",
                "mysql_fetch",
                "ora-",
                "microsoft jet database",
                "sqlite_",
                "postgresql"
            ]
            
            response_lower = response.text.lower()
            if any(indicator in response_lower for indicator in error_indicators):
                vulnerable.append({
                    "payload": payload,
                    "url": test_url,
                    "response_length": len(response.text)
                })
                
        except requests.RequestException as e:
            print(f"Request failed for payload {payload}: {e}")
    
    return vulnerable

# Example usage
if __name__ == "__main__":
    target_url = "http://testphp.vulnweb.com/artists.php"
    test_param = "artist"
    results = test_sql_injection(target_url, test_param)
    
    if results:
        print("Potential SQL injection vulnerabilities found:")
        for result in results:
            print(f"Payload: {result['payload']}")
    else:
        print("No SQL injection vulnerabilities detected")''',

            'port_scanner': '''# Custom Port Scanner
import socket
import threading
from datetime import datetime

class PortScanner:
    def __init__(self, target_host):
        self.target_host = target_host
        self.open_ports = []
        self.lock = threading.Lock()
    
    def scan_port(self, port):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target_host, port))
            
            if result == 0:
                with self.lock:
                    self.open_ports.append(port)
                    print(f"Port {port}: Open")
            
            sock.close()
        except socket.gaierror:
            pass
        except Exception as e:
            pass
    
    def scan_range(self, start_port=1, end_port=1024, threads=100):
        """Scan a range of ports using threading"""
        print(f"Starting port scan on {self.target_host}")
        print(f"Scanning ports {start_port}-{end_port}")
        print(f"Started at: {datetime.now()}")
        
        thread_list = []
        
        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(port,))
            thread_list.append(thread)
            thread.start()
            
            # Limit concurrent threads
            if len(thread_list) >= threads:
                for t in thread_list:
                    t.join()
                thread_list = []
        
        # Wait for remaining threads
        for t in thread_list:
            t.join()
        
        print(f"\\nScan completed at: {datetime.now()}")
        print(f"Open ports found: {sorted(self.open_ports)}")
        return sorted(self.open_ports)

# Example usage
if __name__ == "__main__":
    scanner = PortScanner("127.0.0.1")
    open_ports = scanner.scan_range(1, 1000, 50)''',

            'web_vulnerability_scanner': '''# Basic Web Vulnerability Scanner
import requests
from urllib.parse import urljoin, urlparse
import re

class WebVulnScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.vulnerabilities = []
    
    def check_sql_injection(self, url, params):
        """Check for SQL injection vulnerabilities"""
        payloads = ["'", "1' OR '1'='1", "'; DROP TABLE users--"]
        
        for param in params:
            for payload in payloads:
                test_params = params.copy()
                test_params[param] = payload
                
                try:
                    response = self.session.get(url, params=test_params)
                    if any(error in response.text.lower() for error in 
                          ['sql', 'mysql', 'postgresql', 'oracle']):
                        self.vulnerabilities.append({
                            'type': 'SQL Injection',
                            'url': url,
                            'parameter': param,
                            'payload': payload
                        })
                except Exception:
                    pass
    
    def check_xss(self, url, params):
        """Check for XSS vulnerabilities"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        
        for param in params:
            for payload in xss_payloads:
                test_params = params.copy()
                test_params[param] = payload
                
                try:
                    response = self.session.get(url, params=test_params)
                    if payload in response.text:
                        self.vulnerabilities.append({
                            'type': 'Cross-Site Scripting (XSS)',
                            'url': url,
                            'parameter': param,
                            'payload': payload
                        })
                except Exception:
                    pass
    
    def check_directory_traversal(self, url):
        """Check for directory traversal vulnerabilities"""
        payloads = [
            "../../../etc/passwd",
            "..\\\\..\\\\..\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        for payload in payloads:
            test_url = urljoin(url, payload)
            try:
                response = self.session.get(test_url)
                if "root:" in response.text or "[hosts]" in response.text:
                    self.vulnerabilities.append({
                        'type': 'Directory Traversal',
                        'url': test_url,
                        'payload': payload
                    })
            except Exception:
                pass
    
    def scan(self):
        """Perform comprehensive vulnerability scan"""
        try:
            response = self.session.get(self.base_url)
            
            # Extract forms and parameters
            forms = re.findall(r'<form[^>]*>(.*?)</form>', response.text, re.DOTALL)
            
            # Basic parameter discovery
            params = {'id': '1', 'user': 'admin', 'page': 'index'}
            
            # Run vulnerability checks
            self.check_sql_injection(self.base_url, params)
            self.check_xss(self.base_url, params)
            self.check_directory_traversal(self.base_url)
            
            return self.vulnerabilities
            
        except Exception as e:
            return [{'error': str(e)}]

# Example usage
if __name__ == "__main__":
    scanner = WebVulnScanner("http://testphp.vulnweb.com/")
    vulnerabilities = scanner.scan()
    
    for vuln in vulnerabilities:
        print(f"Vulnerability: {vuln}")'''
        }
    
    def generate_code(self, request: str) -> str:
        """Generate security testing code based on request"""
        request_lower = request.lower()
        
        if 'nmap' in request_lower or 'network scan' in request_lower:
            return self.code_templates['nmap_scan']
        elif 'sql injection' in request_lower:
            return self.code_templates['sql_injection_test']
        elif 'port scan' in request_lower:
            return self.code_templates['port_scanner']
        elif 'web vuln' in request_lower or 'web security' in request_lower:
            return self.code_templates['web_vulnerability_scanner']
        else:
            return '''# Custom Security Script Template
import requests
import socket
import subprocess

def security_test():
    """
    Custom security testing function
    Modify this template based on your specific needs
    """
    print("Security test started...")
    
    # Add your security testing logic here
    # Examples:
    # - Network scanning
    # - Vulnerability testing
    # - Log analysis
    # - Configuration checks
    
    return "Test completed"

if __name__ == "__main__":
    result = security_test()
    print(result)'''