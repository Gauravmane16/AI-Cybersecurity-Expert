import streamlit as st
from config.settings import SECURITY_DOMAINS
from utils.validators import validate_api_key

def render_sidebar():
    """Render the application sidebar"""
    st.sidebar.title("🔒 Cybersecurity AI Expert")
    st.sidebar.markdown("---")
    
    # API Key Input
    st.sidebar.subheader("🔑 Configuration")
    api_key = st.sidebar.text_input(
        "OpenAI API Key",
        type="password",
        help=(
            "Enter your OpenAI API key to use the AI agent.\n\n"
            "To get an API key:\n"
            "1. Go to https://platform.openai.com/account/api-keys\n"
            "2. Sign up or log in to your OpenAI account\n"
            "3. Click on '+ Create new secret key'\n"
            "4. Copy the generated key (you won't be able to see it again)\n"
            "5. Paste it here\n\n"
            "Note: Keep your API key secure and never share it publicly."
        )
    )
    
    if api_key and not validate_api_key(api_key):
        st.sidebar.error("Invalid API key format")
        
    # Add a link to OpenAI platform
    st.sidebar.markdown(
        "[Get OpenAI API Key →](https://platform.openai.com/account/api-keys)",
        unsafe_allow_html=True
    )

    st.sidebar.markdown("---")
    
    # Security Domain Selection
    st.sidebar.subheader("🎯 Security Domain")
    selected_domain = st.sidebar.selectbox(
        "Select Focus Area",
        ["General"] + SECURITY_DOMAINS,
        help="Choose a specific cybersecurity domain for targeted assistance"
    )
    
    # File Upload
    st.sidebar.subheader("📁 File Upload")
    uploaded_file = st.sidebar.file_uploader(
        "Upload logs, configs, or code",
        type=['txt', 'log', 'py', 'js', 'json', 'yaml', 'yml', 'xml'],
        help="Upload files for security analysis"
    )
    
    # Quick Actions
    st.sidebar.subheader("⚡ Quick Actions")
    col1, col2 = st.sidebar.columns(2)
    
    with col1:
        if st.button("🛡️ Scan Tips", use_container_width=True):
            st.session_state.quick_action = "scan_tips"
    
    with col2:
        if st.button("🔧 Tools", use_container_width=True):
            st.session_state.quick_action = "tools"
    
    # Information Panel
    st.sidebar.markdown("---")
    st.sidebar.subheader("ℹ️ About")
    st.sidebar.info(
        "This AI Cybersecurity Expert provides:\n\n"
        "• Security analysis & recommendations\n"
        "• Tool suggestions & code generation\n"
        "• Threat detection & mitigation\n"
        "• Compliance guidance\n"
        "• Best practices & training"
    )
    
    return {
        'api_key': api_key,
        'domain': selected_domain if selected_domain != "General" else None,
        'uploaded_file': uploaded_file
    }