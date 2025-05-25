from typing import Dict, List
import json

class ThreatAnalyzer:
    def __init__(self):
        self.threat_patterns = self._load_threat_patterns()
    
    def _load_threat_patterns(self) -> Dict:
        """Load threat patterns and signatures"""
        return {
            "sql_injection": {
                "patterns": ["' OR '1'='1", "UNION SELECT", "DROP TABLE"],
                "severity": "High",
                "mitigation": ["Input validation", "Parameterized queries", "WAF deployment"]
            },
            "xss": {
                "patterns": ["<script>", "javascript:", "onerror="],
                "severity": "Medium",
                "mitigation": ["Output encoding", "CSP headers", "Input sanitization"]
            },
            "command_injection": {
                "patterns": ["; cat /etc/passwd", "| whoami", "&& ls"],
                "severity": "Critical",
                "mitigation": ["Input validation", "Command sanitization", "Least privilege"]
            }
        }
    
    def analyze_log_entry(self, log_entry: str) -> Dict:
        """Analyze a log entry for potential threats"""
        threats_detected = []
        
        for threat_type, info in self.threat_patterns.items():
            for pattern in info["patterns"]:
                if pattern.lower() in log_entry.lower():
                    threats_detected.append({
                        "type": threat_type,
                        "severity": info["severity"],
                        "pattern_matched": pattern,
                        "mitigation": info["mitigation"]
                    })
        
        return {
            "log_entry": log_entry,
            "threats_detected": threats_detected,
            "risk_level": self._calculate_risk_level(threats_detected)
        }
    
    def _calculate_risk_level(self, threats: List[Dict]) -> str:
        """Calculate overall risk level based on detected threats"""
        if not threats:
            return "Low"
        
        severity_scores = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        max_severity = max([severity_scores.get(t["severity"], 1) for t in threats])
        
        if max_severity >= 4:
            return "Critical"
        elif max_severity >= 3:
            return "High"
        elif max_severity >= 2:
            return "Medium"
        else:
            return "Low"