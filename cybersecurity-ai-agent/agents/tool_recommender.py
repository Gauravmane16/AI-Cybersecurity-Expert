from typing import List, Dict
from config.settings import SECURITY_TOOLS, SECURITY_DOMAINS, SecurityDomains

class ToolRecommender:
    def __init__(self):
        self.tools_db = SECURITY_TOOLS
    
    def get_tools_for_domain(self, domain: str) -> List[str]:
        """Get recommended tools for a specific security domain"""
        return self.tools_db.get(domain, [])
    
    def recommend_tools_for_task(self, task_description: str) -> Dict[str, List[str]]:
        """
        Recommend tools based on task description using keyword matching
        
        Args:
            task_description (str): Description of the security task
            
        Returns:
            Dict[str, List[str]]: Dictionary mapping security domains to recommended tools
        """
        recommendations = {}
        
        task_lower = task_description.lower()
        
        # Keyword-based tool recommendation
        keywords_map = {
            'network': SecurityDomains.NETWORK_SECURITY,
            'web': SecurityDomains.APPLICATION_SECURITY,
            'api': SecurityDomains.APPLICATION_SECURITY,
            'cloud': SecurityDomains.CLOUD_SECURITY,
            'aws': SecurityDomains.CLOUD_SECURITY,
            'azure': SecurityDomains.CLOUD_SECURITY,
            'malware': SecurityDomains.MALWARE_ANALYSIS,
            'endpoint': SecurityDomains.ENDPOINT_PROTECTION,
            'penetration': SecurityDomains.PENETRATION_TESTING,
            'pentest': SecurityDomains.PENETRATION_TESTING,
            'compliance': SecurityDomains.COMPLIANCE,
            'devsecops': SecurityDomains.DEVSECOPS,
            'secure coding': SecurityDomains.SECURE_CODING
        }
        
        for keyword, domain in keywords_map.items():
            if keyword in task_lower:
                recommendations[domain] = self.get_tools_for_domain(domain)
        
        return recommendations if recommendations else {"General": ["Nmap", "OWASP ZAP", "Wireshark"]}
