import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
from typing import Dict, List

def render_threat_dashboard(threats_data: List[Dict]):
    """Render threat analysis dashboard"""
    if not threats_data:
        st.info("No threats detected")
        return
    
    # Threat severity distribution
    severity_counts = {}
    for threat in threats_data:
        severity = threat.get('severity', 'Unknown')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    # Create pie chart
    fig = px.pie(
        values=list(severity_counts.values()),
        names=list(severity_counts.keys()),
        title="Threat Severity Distribution"
    )
    st.plotly_chart(fig, use_container_width=True)
    
    # Threat details table
    st.subheader("Threat Details")
    for i, threat in enumerate(threats_data):
        with st.expander(f"Threat {i+1}: {threat.get('type', 'Unknown')}"):
            col1, col2 = st.columns(2)
            with col1:
                st.write(f"**Severity:** {threat.get('severity', 'Unknown')}")
                st.write(f"**Type:** {threat.get('type', 'Unknown')}")
            with col2:
                st.write(f"**Pattern:** {threat.get('pattern_matched', 'N/A')}")
                st.write(f"**Risk Level:** {threat.get('risk_level', 'Unknown')}")
            
            if 'mitigation' in threat:
                st.write("**Mitigation Steps:**")
                for step in threat['mitigation']:
                    st.write(f"• {step}")

def render_code_snippet(code: str, language: str = "python"):
    """Render code snippet with copy functionality"""
    st.code(code, language=language)
    
    # Copy button functionality would require JavaScript, 
    # so we'll provide download option instead
    st.download_button(
        label="📥 Download Code",
        data=code,
        file_name=f"security_script.{language}",
        mime="text/plain"
    )

def render_security_metrics(metrics: Dict):
    """Render security metrics visualization"""
    if not metrics:
        return
    
    # Create metrics cards
    cols = st.columns(len(metrics))
    for i, (key, value) in enumerate(metrics.items()):
        with cols[i]:
            st.metric(
                label=key.replace('_', ' ').title(),
                value=value,
                delta=None
            )
