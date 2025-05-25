from langchain.agents import AgentType, initialize_agent
from langchain.memory import ConversationBufferMemory
from langchain_openai import ChatOpenAI
from langchain.tools import Tool
from typing import List, Dict, Any
import json

class CybersecurityAgent:
    def __init__(self, openai_api_key: str, model: str = "gpt-4"):
        """Initialize the cybersecurity agent"""
        self.llm = ChatOpenAI(
            api_key=openai_api_key,
            model=model,
            temperature=0.1
        )
        self.memory = ConversationBufferMemory(
            memory_key="chat_history",
            return_messages=True
        )
        self.tools = self._initialize_tools()
        self.agent = self._create_agent()
    
    def _initialize_tools(self) -> List[Tool]:
        from tools.security_tools import SecurityToolRecommender
        from tools.code_generator import SecurityCodeGenerator
        
        tool_recommender = SecurityToolRecommender()
        code_generator = SecurityCodeGenerator()
        
        return [
            Tool(
                name="recommend_security_tools",
                description="Recommend appropriate cybersecurity tools for specific domains or tasks",
                func=tool_recommender.recommend_tools
            ),
            Tool(
                name="generate_security_code",
                description="Generate security testing code snippets and scripts",
                func=code_generator.generate_code
            ),
            Tool(
                name="analyze_threat",
                description="Analyze threats and provide mitigation strategies",
                func=self._analyze_threat
            )
        ]
    
    def _create_agent(self):
        system_prompt = """
        You are a Senior Cybersecurity Expert and Consultant with extensive experience in:
        - Network Security and Infrastructure Protection
        - Application Security and Secure Development
        - Cloud Security Architecture
        - Endpoint Protection and Malware Analysis
        - Penetration Testing and Vulnerability Assessment
        - Threat Detection, Incident Response, and Mitigation
        - Compliance and Regulatory Standards (GDPR, HIPAA, ISO 27001, etc.)
        - DevSecOps and Security Integration
        
        Your role is to:
        1. Provide expert cybersecurity advice and solutions
        2. Recommend appropriate tools for specific security tasks
        3. Generate secure code examples and testing scripts
        4. Analyze threats and provide actionable mitigation strategies
        5. Explain complex security concepts in accessible terms
        6. Stay current with the latest cybersecurity trends and threats
        
        Always prioritize:
        - Security best practices
        - Ethical considerations
        - Practical, actionable advice
        - Clear explanations with examples
        - Up-to-date threat intelligence
        
        Format your responses with:
        - Clear structure and headings
        - Code examples when relevant
        - Tool recommendations
        - Step-by-step instructions
        - Risk assessments and mitigation strategies
        """
        
        return initialize_agent(
            tools=self.tools,
            llm=self.llm,
            agent=AgentType.CONVERSATIONAL_REACT_DESCRIPTION,
            memory=self.memory,
            verbose=True,
            agent_kwargs={"system_message": system_prompt}
        )
    
    def _analyze_threat(self, threat_description: str) -> str:
        """Analyze threat and provide mitigation strategies"""
        analysis_prompt = f"""
        Analyze the following cybersecurity threat or vulnerability:
        
        {threat_description}
        
        Provide:
        1. Threat Classification and Severity
        2. Potential Impact Assessment
        3. Attack Vectors and Methods
        4. Immediate Mitigation Steps
        5. Long-term Prevention Strategies
        6. Recommended Tools and Technologies
        7. Compliance Considerations
        """
        
        response = self.llm.invoke(analysis_prompt)
        return response.content
    
    def chat(self, message: str, domain: str = None) -> str:
        """Main chat interface with the cybersecurity agent"""
        try:
            context = f"Security Domain: {domain}\n\n" if domain else ""
            full_message = context + message
            
            response = self.agent.run(input=full_message)
            return response
        except Exception as e:
            return f"Error processing request: {str(e)}"
