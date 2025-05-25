import json
import yaml
import xml.etree.ElementTree as ET
from typing import Dict, Any, List

class FileHandler:
    @staticmethod
    def read_json(content: str) -> Dict[Any, Any]:
        """Parse JSON content"""
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON format: {str(e)}")
    
    @staticmethod
    def read_yaml(content: str) -> Dict[Any, Any]:
        """Parse YAML content"""
        try:
            return yaml.safe_load(content)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML format: {str(e)}")
    
    @staticmethod
    def read_xml(content: str) -> ET.Element:
        """Parse XML content"""
        try:
            return ET.fromstring(content)
        except ET.ParseError as e:
            raise ValueError(f"Invalid XML format: {str(e)}")
    
    @staticmethod
    def analyze_log_file(content: str) -> List[Dict]:
        """Analyze log file for security events"""
        lines = content.split('\n')
        events = []
        
        for line_num, line in enumerate(lines, 1):
            if not line.strip():
                continue
            
            # Look for common security indicators
            indicators = {
                'failed_login': ['failed login', 'authentication failed', 'login failed'],
                'suspicious_ip': ['blocked ip', 'suspicious activity'],
                'malware': ['virus detected', 'malware', 'trojan'],
                'intrusion': ['intrusion detected', 'unauthorized access']
            }
            
            for event_type, keywords in indicators.items():
                if any(keyword in line.lower() for keyword in keywords):
                    events.append({
                        'line_number': line_num,
                        'event_type': event_type,
                        'content': line.strip(),
                        'severity': 'high' if event_type in ['malware', 'intrusion'] else 'medium'
                    })
        
        return events