import streamlit as st
from typing import Dict, Any
import json

def render_main_interface(sidebar_data: Dict[str, Any], agent):
    """Render the main application interface"""
    
    # Add page selection to sidebar
    with st.sidebar:
        page = st.radio(
            "Navigation",
            ["Main Dashboard", "Information & Resources"]
        )
    
    if page == "Main Dashboard":
        # Header
        st.title("🔒 AI Cybersecurity Expert")
        st.markdown("*Your intelligent cybersecurity consultant powered by advanced AI*")
        
        # Quick Action Handlers
        if hasattr(st.session_state, 'quick_action'):
            if st.session_state.quick_action == "scan_tips":
                render_scan_tips()
            elif st.session_state.quick_action == "tools":
                render_tools_section()
            delattr(st.session_state, 'quick_action')
        
        # File Analysis Section
        if sidebar_data['uploaded_file'] is not None:
            render_file_analysis(sidebar_data['uploaded_file'], agent)
        
        # Chat Interface
        render_chat_interface(sidebar_data, agent)
    
    else:  # Information & Resources page
        st.title("📚 Information & Resources")
        render_info_tabs()

def render_scan_tips():
    """Render security scanning tips"""
    st.subheader("🛡️ Security Scanning Tips")
    
    tips = {
        "Network Scanning": [
            "Start with host discovery: `nmap -sn 192.168.1.0/24`",
            "Use stealth scans to avoid detection: `nmap -sS -T2`",
            "Always get proper authorization before scanning"
        ],
        "Web Application Testing": [
            "Begin with automated scanners like OWASP ZAP",
            "Test for OWASP Top 10 vulnerabilities",
            "Check for SSL/TLS configuration issues"
        ],
        "Vulnerability Assessment": [
            "Use multiple tools for comprehensive coverage",
            "Prioritize vulnerabilities by CVSS scores",
            "Validate findings to reduce false positives"
        ]
    }
    
    for category, tip_list in tips.items():
        with st.expander(f"💡 {category}"):
            for tip in tip_list:
                st.write(f"• {tip}")

def render_tools_section():
    """Render cybersecurity tools information"""
    st.subheader("🔧 Cybersecurity Tools")
    
    from config.settings import SECURITY_TOOLS
    
    for domain, tools in SECURITY_TOOLS.items():
        with st.expander(f"🎯 {domain}"):
            cols = st.columns(2)
            for i, tool in enumerate(tools):
                with cols[i % 2]:
                    st.write(f"• **{tool}**")

def render_file_analysis(uploaded_file, agent):
    """Render file analysis section"""
    st.subheader("📁 File Analysis")
    
    if uploaded_file is not None:
        # Display file info
        st.info(f"Analyzing: {uploaded_file.name} ({uploaded_file.size} bytes)")
        
        try:
            # Read file content
            if uploaded_file.type == "text/plain" or uploaded_file.name.endswith(('.log', '.txt')):
                content = str(uploaded_file.read(), "utf-8")
                
                # Show preview
                with st.expander("📋 File Preview"):
                    st.text_area("Content", content[:1000] + "..." if len(content) > 1000 else content, height=200)
                
                # Analyze with AI
                if st.button("🔍 Analyze File for Security Issues"):
                    with st.spinner("Analyzing file..."):
                        analysis_prompt = f"""
                        Analyze the following file content for cybersecurity issues:
                        
                        Filename: {uploaded_file.name}
                        Content:
                        {content[:5000]}  # Limit content to avoid token limits
                        
                        Please identify:
                        1. Potential security vulnerabilities
                        2. Suspicious patterns or activities
                        3. Compliance issues
                        4. Recommendations for improvement
                        """
                        
                        if agent:
                            analysis = agent.chat(analysis_prompt)
                            st.success("Analysis Complete!")
                            st.markdown("### 🔍 Security Analysis Results")
                            st.markdown(analysis)
                        else:
                            st.error("Please enter your OpenAI API key to analyze files")
            
            else:
                st.warning("File type not supported for analysis. Supported: .txt, .log")
                
        except Exception as e:
            st.error(f"Error reading file: {str(e)}")

def render_chat_interface(sidebar_data, agent):
    """Render the main chat interface"""
    st.subheader("💬 Chat with Cybersecurity Expert")
    
    # Initialize chat history
    if "messages" not in st.session_state:
        st.session_state.messages = [
            {
                "role": "assistant",
                "content": "Hello! I'm your AI Cybersecurity Expert. I can help you with:\n\n"
                          "🛡️ Security assessments and recommendations\n"
                          "🔧 Tool selection and usage guidance\n"
                          "💻 Security code generation and review\n"
                          "🚨 Threat analysis and mitigation strategies\n"
                          "📋 Compliance and best practices\n\n"
                          "What cybersecurity challenge can I help you with today?"
            }
        ]
    
    # Display chat messages
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
    
    # Chat input
    if prompt := st.chat_input("Ask me anything about cybersecurity..."):
        # Add user message to chat history
        st.session_state.messages.append({"role": "user", "content": prompt})
        
        # Display user message
        with st.chat_message("user"):
            st.markdown(prompt)
        
        # Generate assistant response
        with st.chat_message("assistant"):
            if sidebar_data['api_key']:
                try:
                    with st.spinner("Thinking..."):
                        if agent is None:
                            from agents.cybersecurity_agent import CybersecurityAgent
                            agent = CybersecurityAgent(sidebar_data['api_key'])
                        
                        response = agent.chat(prompt, sidebar_data['domain'])
                        st.markdown(response)
                        
                        # Add assistant response to chat history
                        st.session_state.messages.append({"role": "assistant", "content": response})
                
                except Exception as e:
                    error_msg = f"Error: {str(e)}"
                    st.error(error_msg)
                    st.session_state.messages.append({"role": "assistant", "content": error_msg})
            else:
                error_msg = "Please enter your OpenAI API key in the sidebar to start chatting."
                st.error(error_msg)
                st.session_state.messages.append({"role": "assistant", "content": error_msg})

def render_info_tabs():
    """Render information tabs"""
    st.markdown("---")
    
    tab1, tab2, tab3, tab4 = st.tabs(["🎯 Use Cases", "🔧 Tools Reference", "📚 Resources", "⚠️ Disclaimer"])
    
    with tab1:
        st.subheader("Common Use Cases")
        use_cases = [
            "**Vulnerability Assessment**: Get guidance on scanning and identifying security weaknesses",
            "**Incident Response**: Analyze security incidents and get remediation steps",
            "**Compliance Auditing**: Understand requirements for GDPR, HIPAA, SOX, etc.",
            "**Secure Development**: Review code for security issues and get secure coding practices",
            "**Network Security**: Design and implement network security controls",
            "**Cloud Security**: Secure cloud infrastructure and services",
            "**Threat Hunting**: Identify and investigate potential security threats",
            "**Security Training**: Learn cybersecurity concepts and best practices"
        ]
        
        for use_case in use_cases:
            st.markdown(f"• {use_case}")
    
    with tab2:
        st.subheader("Tools Reference")
        
        tool_categories = {
            "🌐 Network Security": ["Nmap", "Wireshark", "Netcat", "TCPDump"],
            "🔍 Vulnerability Scanning": ["Nessus", "OpenVAS", "Nikto", "OWASP ZAP"],
            "🎯 Penetration Testing": ["Metasploit", "Burp Suite", "SQLMap", "BeEF"],
            "🔬 Malware Analysis": ["Ghidra", "IDA Pro", "Volatility", "YARA"],
            "☁️ Cloud Security": ["Scout Suite", "Prowler", "CloudMapper", "Pacu"]
        }
        
        for category, tools in tool_categories.items():
            st.markdown(f"**{category}**")
            for tool in tools:
                st.markdown(f"  • {tool}")
            st.markdown("")
    
    with tab3:
        st.subheader("Cybersecurity Resources")
        
        resources = [
            "**OWASP** - Open Web Application Security Project",
            "**NIST Cybersecurity Framework** - Risk management guidelines",
            "**SANS Institute** - Security training and certification",
            "**CVE Database** - Common Vulnerabilities and Exposures",
            "**MITRE ATT&CK** - Adversarial tactics and techniques",
            "**CIS Controls** - Critical Security Controls",
            "**ISO 27001** - Information security management standard"
        ]
        
        for resource in resources:
            st.markdown(f"• {resource}")
    
    with tab4:
        st.warning(
            "**Important Disclaimer:**\n\n"
            "• This tool is for educational and authorized testing purposes only\n"
            "• Always obtain proper authorization before conducting security tests\n"
            "• The generated code and recommendations should be reviewed by security professionals\n"
            "• Users are responsible for compliance with applicable laws and regulations\n"
            "• This tool does not replace professional cybersecurity consulting"
        )
