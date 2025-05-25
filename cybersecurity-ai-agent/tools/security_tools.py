from typing import Dict, List
from config.settings import SECURITY_TOOLS, SECURITY_DOMAINS

class SecurityToolRecommender:
    def __init__(self):
        self.tools_database = SECURITY_TOOLS
    
    def recommend_tools(self, query: str) -> str:
        """Recommend security tools based on user query"""
        query_lower = query.lower()
        recommendations = []
        
        # Domain-specific recommendations
        for domain, tools in self.tools_database.items():
            domain_keywords = domain.lower().split()
            if any(keyword in query_lower for keyword in domain_keywords):
                recommendations.append(f"\n**{domain}:**\n" + "\n".join([f"• {tool}" for tool in tools]))
        
        # Task-specific recommendations
        task_tools = {
            'vulnerability scan': ['Nessus', 'OpenVAS', 'Nmap', 'OWASP ZAP'],
            'web security': ['Burp Suite', 'OWASP ZAP', 'SQLMap', 'Nikto'],
            'network analysis': ['Wireshark', 'TCPDump', 'Nmap', 'Netcat'],
            'malware analysis': ['Ghidra', 'IDA Pro', 'Volatility', 'YARA'],
            'penetration testing': ['Metasploit', 'Cobalt Strike', 'Empire', 'BeEF']
        }
        
        for task, tools in task_tools.items():
            if task in query_lower:
                recommendations.append(f"\n**Recommended for {task.title()}:**\n" + 
                                     "\n".join([f"• {tool}" for tool in tools]))
        
        if not recommendations:
            recommendations.append("**General Security Tools:**\n• Nmap\n• OWASP ZAP\n• Wireshark\n• Metasploit")
        
        return "\n".join(recommendations)