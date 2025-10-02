import streamlit as st
import pandas as pd
import json
import re
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
from typing import Dict, List, Any
import numpy as np
from openai import OpenAI
import httpx
import base64
import io
import os
import glob
import time
from fpdf import FPDF
import ocr_processor

# Page configuration
st.set_page_config(
    page_title="CyberSec AI - Incident Analysis",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ========== New: Config for logs folder ==========
LOGS_DIR = "logs"
os.makedirs(LOGS_DIR, exist_ok=True)

# Initialize session state
if 'incidents' not in st.session_state:
    st.session_state.incidents = []
if 'current_incident' not in st.session_state:
    st.session_state.current_incident = None
if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []
if 'raw_logs' not in st.session_state:
    st.session_state.raw_logs = ""
# ========== New: registry for auto-loaded incidents ==========
if 'loaded_incidents' not in st.session_state:
    st.session_state.loaded_incidents = {}
if 'logs_scanned' not in st.session_state:
    st.session_state.logs_scanned = False

# Initialize AI client
def initialize_ai_client():
    """Initialize AI client for cybersecurity analysis"""
    try:
        client = httpx.Client(verify=False)
        return OpenAI(
            base_url="https://genailab.tcs.in",
            api_key="sk-h8b9XM-6gT6Mli",
            http_client=client
        )
    except Exception as e:
        st.error(f"AI client initialization failed: {str(e)}")
        return None

def analyze_incident_with_ai(raw_logs: str, log_format: str = "auto"):
    """Use AI to analyze security logs and generate incident report"""
    ai_client = initialize_ai_client()
    if not ai_client:
        return None
    
    prompt = f"""
    You are a senior cybersecurity analyst. Analyze the following security logs and generate a comprehensive incident report.
    
    LOG FORMAT: {log_format}
    RAW LOGS:
    {raw_logs}
    
    Please provide a structured analysis in JSON format with the following fields:
    {{
        "incident_summary": "Brief overview of the incident",
        "severity_level": "Low/Medium/High/Critical",
        "attack_type": "Specific attack classification",
        "timeline": {{
            "start_time": "YYYY-MM-DD HH:MM:SS",
            "end_time": "YYYY-MM-DD HH:MM:SS",
            "duration": "X hours/minutes"
        }},
        "affected_assets": ["list of affected systems/assets"],
        "indicators_of_compromise": [{{
            "type": "IP/URL/Hash/User",
            "value": "specific indicator",
            "confidence": "High/Medium/Low"
        }}],
        "attack_vector": "Detailed description of how the attack occurred",
        "impact_assessment": "Business/technical impact analysis",
        "mitigation_steps": [
            "Step 1: Immediate containment actions",
            "Step 2: Eradication steps", 
            "Step 3: Recovery procedures",
            "Step 4: Preventive measures"
        ],
        "confidence_score": 0.95,
        "recommendations": ["Long-term security improvements"]
    }}
    
    Ensure the analysis is accurate and actionable for cybersecurity professionals.
    """
    
    try:
        response = ai_client.chat.completions.create(
            model="azure_ai/genailab-maas-DeepSeek-V3-0324",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert specializing in incident analysis and digital forensics."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=2000,
            temperature=0.1
        )
        
        # Extract JSON from response
        content = response.choices[0].message.content
        json_match = re.search(r'\{.*\}', content, re.DOTALL)
        if json_match:
            return json.loads(json_match.group())
        else:
            # Fallback: try to parse as plain text
            return {"raw_analysis": content}
            
    except Exception as e:
        st.error(f"AI analysis failed: {str(e)}")
        return None

def generate_incident_report(incident_data: Dict) -> str:
    """Generate human-readable incident report"""
    report = f"""
# CYBERSECURITY INCIDENT REPORT
**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Incident ID:** {incident_data.get('incident_id', 'N/A')}

## Executive Summary
{incident_data.get('incident_summary', 'N/A')}

## Severity Assessment
- **Level:** {incident_data.get('severity_level', 'N/A')}
- **Confidence Score:** {incident_data.get('confidence_score', 'N/A')}

## Attack Details
- **Type:** {incident_data.get('attack_type', 'N/A')}
- **Vector:** {incident_data.get('attack_vector', 'N/A')}

## Timeline
- **Start:** {incident_data.get('timeline', {}).get('start_time', 'N/A')}
- **End:** {incident_data.get('timeline', {}).get('end_time', 'N/A')}
- **Duration:** {incident_data.get('timeline', {}).get('duration', 'N/A')}

## Affected Assets
{chr(10).join(['- ' + asset for asset in incident_data.get('affected_assets', [])])}

## Indicators of Compromise
"""
    
    for ioc in incident_data.get('indicators_of_compromise', []):
        report += f"- **{ioc.get('type', 'N/A')}:** {ioc.get('value', 'N/A')} (Confidence: {ioc.get('confidence', 'N/A')})\n"
    
    report += f"""
## Impact Assessment
{incident_data.get('impact_assessment', 'N/A')}

## IMMEDIATE MITIGATION STEPS
"""
    
    for i, step in enumerate(incident_data.get('mitigation_steps', []), 1):
        report += f"{i}. {step}\n"
    
    report += f"""
## RECOMMENDATIONS
{chr(10).join(['- ' + rec for rec in incident_data.get('recommendations', [])])}

## RAW ANALYSIS NOTES
{incident_data.get('raw_analysis', 'No additional notes')}
"""
    return report

def chat_with_incident_data(question: str, incident_data: Dict, chat_history: List) -> str:
    """AI-powered Q&A about the incident"""
    ai_client = initialize_ai_client()
    if not ai_client:
        return "AI service unavailable."
    
    # Prepare context from incident data
    context = f"""
    Incident Context:
    - Summary: {incident_data.get('incident_summary', 'N/A')}
    - Attack Type: {incident_data.get('attack_type', 'N/A')}
    - Severity: {incident_data.get('severity_level', 'N/A')}
    - Affected Assets: {', '.join(incident_data.get('affected_assets', []))}
    - Timeline: {incident_data.get('timeline', {}).get('start_time', 'N/A')} to {incident_data.get('timeline', {}).get('end_time', 'N/A')}
    """
    
    prompt = f"""
    You are a cybersecurity incident response analyst. Answer the user's question based on the incident context below.
    
    {context}
    
    Previous conversation:
    {chr(10).join([f"{msg['role']}: {msg['content']}" for msg in chat_history[-5:]])}
    
    Current question: {question}
    
    Provide a concise, technical answer focused on incident response and cybersecurity best practices.
    """
    
    try:
        response = ai_client.chat.completions.create(
            model="azure_ai/genailab-maas-DeepSeek-V3-0324",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert helping with incident analysis."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=500,
            temperature=0.3
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Error generating response: {str(e)}"

def create_visualizations(incident_data: Dict):
    """Create interactive visualizations for the incident"""
    # Severity gauge
    severity_levels = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    severity_value = severity_levels.get(incident_data.get('severity_level', 'Low'), 1)
    
    fig_gauge = go.Figure(go.Indicator(
        mode = "gauge+number+delta",
        value = severity_value,
        domain = {'x': [0, 1], 'y': [0, 1]},
        title = {'text': "Incident Severity"},
        delta = {'reference': 2},
        gauge = {
            'axis': {'range': [None, 4], 'tickvals': [1, 2, 3, 4], 'ticktext': ['Low', 'Medium', 'High', 'Critical']},
            'bar': {'color': "darkblue"},
            'steps': [
                {'range': [0, 1], 'color': "lightgray"},
                {'range': [1, 2], 'color': "yellow"},
                {'range': [2, 3], 'color': "orange"},
                {'range': [3, 4], 'color': "red"}
            ]
        }
    ))
    
    # IOC types pie chart
    ioc_types = {}
    for ioc in incident_data.get('indicators_of_compromise', []):
        ioc_type = ioc.get('type', 'Unknown')
        ioc_types[ioc_type] = ioc_types.get(ioc_type, 0) + 1
    
    if ioc_types:
        fig_pie = px.pie(
            values=list(ioc_types.values()),
            names=list(ioc_types.keys()),
            title="Indicators of Compromise Distribution"
        )
    else:
        fig_pie = px.pie(title="No IOCs Available")
    
    return fig_gauge, fig_pie

# ========== New: helpers to load logs and auto-analyze ==========
def scan_logs_folder(folder: str = LOGS_DIR):
    """Return list of file paths in logs folder with supported extensions."""
    paths = []
    for ext in ("*.txt", "*.log", "*.json"):
        paths.extend(glob.glob(os.path.join(folder, ext)))
    return sorted(paths)

def auto_analyze_logs_on_start():
    """Scan logs folder and analyze each file once per session."""
    if st.session_state.logs_scanned:
        return
    files = scan_logs_folder()
    if not files:
        st.session_state.logs_scanned = True
        return

    st.info(f"Found {len(files)} file(s) in '{LOGS_DIR}'. Analyzing...")
    for path in files:
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
        except UnicodeDecodeError:
            with open(path, "r", encoding="latin-1") as f:
                content = f.read()
        except Exception as e:
            st.warning(f"Could not read {path}: {e}")
            continue

        filename = os.path.basename(path)
        incident_id = f"INC-{os.path.splitext(filename)[0]}"
        # Heuristic: infer log_format from name
        name_lower = filename.lower()
        if "firewall" in name_lower:
            log_format = "Firewall"
        elif "web" in name_lower:
            log_format = "Web Server"
        elif "brute" in name_lower or "auth" in name_lower:
            log_format = "Auth"
        elif "malware" in name_lower or "av" in name_lower:
            log_format = "AV/EDR"
        else:
            log_format = "auto"

        analysis = analyze_incident_with_ai(content, log_format=log_format)
        if analysis:
            analysis["incident_id"] = incident_id
            st.session_state.loaded_incidents[incident_id] = {
                "file": filename,
                "path": path,
                "log_format": log_format,
                "raw": content,
                "analysis": analysis
            }
    st.success("Auto-analysis completed.")
    st.session_state.logs_scanned = True

def markdown_to_pdf_bytes(md_text: str) -> bytes:
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_font("Arial", "B", 18)
    pdf.set_text_color(40, 40, 120)
    pdf.cell(0, 15, "CYBERSECURITY INCIDENT REPORT", ln=True, align="C")
    pdf.set_draw_color(40, 40, 120)
    pdf.set_line_width(0.8)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(8)

    pdf.set_font("Arial", "", 12)
    pdf.set_text_color(0, 0, 0)

    # Section mapping for better formatting
    section_titles = [
        "Executive Summary",
        "Severity Assessment",
        "Attack Details",
        "Timeline",
        "Affected Assets",
        "Indicators of Compromise",
        "Impact Assessment",
        "IMMEDIATE MITIGATION STEPS",
        "RECOMMENDATIONS",
        "RAW ANALYSIS NOTES"
    ]

    for line in md_text.split('\n'):
        line_strip = line.strip()
        if line_strip.startswith("# "):
            continue  # Already added main title
        elif line_strip.startswith("## "):
            section = line_strip.replace("## ", "")
            if section in section_titles:
                pdf.ln(4)
                pdf.set_font("Arial", "B", 14)
                pdf.set_text_color(40, 40, 120)
                pdf.cell(0, 10, section, ln=True)
                pdf.set_font("Arial", "", 12)
                pdf.set_text_color(0, 0, 0)
            else:
                pdf.ln(2)
                pdf.set_font("Arial", "B", 12)
                pdf.cell(0, 8, section, ln=True)
                pdf.set_font("Arial", "", 12)
        elif line_strip.startswith("- "):
            pdf.cell(8)  # Indent
            pdf.multi_cell(0, 8, "- " + line_strip[2:])
        elif line_strip and line_strip[0].isdigit() and line_strip[1] == ".":
            pdf.cell(8)
            pdf.multi_cell(0, 8, line_strip)
        elif line_strip.startswith("**") and line_strip.endswith("**"):
            pdf.set_font("Arial", "B", 12)
            pdf.multi_cell(0, 8, line_strip.replace("**", ""))
            pdf.set_font("Arial", "", 12)
        elif line_strip.startswith("**") and "**" in line_strip[2:]:
            # Bold label, normal value
            parts = line_strip.split("**")
            pdf.set_font("Arial", "B", 12)
            pdf.write(8, parts[1] + ": ")
            pdf.set_font("Arial", "", 12)
            pdf.multi_cell(0, 8, "".join(parts[2:]).strip(": "))
        elif line_strip == "":
            pdf.ln(2)
        else:
            pdf.multi_cell(0, 8, line_strip)

    pdf_output = pdf.output(dest='S').encode('latin1')
    return pdf_output

def main():
    # Custom CSS
    st.markdown("""
    <style>
    .main-header {
        font-size: 2.5rem;
        color: #FF6B6B;
        text-align: center;
        margin-bottom: 2rem;
    }
    .section-header {
        font-size: 1.5rem;
        color: #4ECDC4;
        border-bottom: 2px solid #4ECDC4;
        padding-bottom: 0.5rem;
        margin-top: 2rem;
    }
    .critical-alert {
        background-color: #FFE6E6;
        color: #D8000C;
        padding: 1rem;
        border-radius: 0.5rem;
        border: 1px solid #FFBABA;
    }
    .success-box {
        background-color: #E6FFE6;
        color: #006400;
        padding: 1rem;
        border-radius: 0.5rem;
        border: 1px solid #BDFFBD;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Header
    st.markdown('<div class="main-header">🛡️ CyberSec AI - Incident Analysis Platform</div>', unsafe_allow_html=True)

    # ========== New: auto-analyze logs on first load ==========
    auto_analyze_logs_on_start()

    # Sidebar
    with st.sidebar:
        st.image("https://cdn-icons-png.flaticon.com/512/2342/2342116.png", width=80)
        st.title("Navigation")
        
        menu = st.radio("Select Module", [
            "📊 Dashboard",
            "🔍 New Incident Analysis", 
            "💬 Incident Q&A",
            "📈 Reports & Analytics",
            "⚙️ Settings"
        ])
        
        st.markdown("---")
        st.info("**Quick Stats**")
        st.write(f"📈 Incidents Analyzed (session): {len(st.session_state.incidents)}")
        if st.session_state.incidents:
            severities = [inc.get('severity_level', 'Low') for inc in st.session_state.incidents]
            critical_count = severities.count('Critical') + severities.count('High')
            st.write(f"🚨 Critical/High: {critical_count}")

        # ========== New: Rescan button ==========
        if st.button("🔄 Rescan logs folder"):
            st.session_state.loaded_incidents = {}
            st.session_state.logs_scanned = False
            st.rerun()
    
    # Dashboard
    if menu == "📊 Dashboard":
        st.markdown('<div class="section-header">Security Incident Dashboard</div>', unsafe_allow_html=True)
        
        if not st.session_state.incidents and not st.session_state.loaded_incidents:
            st.info("No incidents analyzed yet. Use New Incident Analysis or add files to logs/ and rescan.")
            
            # Sample data for demonstration
            if st.button("Load Sample Incident Data"):
                sample_logs = """
                [2024-01-15 14:23:45] SECURITY ALERT: Multiple failed login attempts from IP 192.168.1.100
                [2024-01-15 14:24:10] SUSPICIOUS ACTIVITY: User 'admin' attempted privilege escalation
                [2024-01-15 14:25:30] MALWARE DETECTED: Trojan:Win32/Agent.XX identified on server SRV-APP-01
                [2024-01-15 14:26:15] NETWORK SCAN: Port scanning detected from IP 103.216.88.45
                [2024-01-15 14:30:00] DATA EXFILTRATION: 2.5GB of sensitive data transferred to external IP
                """
                st.session_state.raw_logs = sample_logs
                st.rerun()
        else:
            # Stats from session incidents
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Session Incidents", len(st.session_state.incidents))
            with col2:
                high_severity = len([inc for inc in st.session_state.incidents if inc.get('severity_level') in ['High', 'Critical']])
                st.metric("High Severity (session)", high_severity)
            with col3:
                if st.session_state.incidents:
                    avg_conf = np.mean([inc.get('confidence_score', 0) for inc in st.session_state.incidents])
                else:
                    avg_conf = 0
                st.metric("Avg Confidence (session)", f"{avg_conf:.2f}")

            # Table for recent session incidents
            if st.session_state.incidents:
                st.subheader("Recent Session Incidents")
                rec = []
                for inc in st.session_state.incidents[-5:]:
                    rec.append({
                        'ID': inc.get('incident_id', 'N/A'),
                        'Type': inc.get('attack_type', 'N/A'),
                        'Severity': inc.get('severity_level', 'N/A'),
                        'Assets': len(inc.get('affected_assets', [])),
                        'IOCs': len(inc.get('indicators_of_compromise', [])),
                        'Time': inc.get('timeline', {}).get('start_time', 'N/A')
                    })
                st.dataframe(pd.DataFrame(rec), use_container_width=True)

            # New: Summary of auto-loaded incidents
            if st.session_state.loaded_incidents:
                st.subheader("Auto-Loaded Incidents (from logs/)")
                loaded_ids = list(st.session_state.loaded_incidents.keys())
                st.write(f"Detected and analyzed: {len(loaded_ids)} file(s)")
    
    # New Incident Analysis
    elif menu == "🔍 New Incident Analysis":
        st.markdown('<div class="section-header">AI-Powered Incident Analysis</div>', unsafe_allow_html=True)
        
        # Log input methods
        # input_method = st.radio("Log Input Method", ["Text Input", "File Upload", "Sample Data"])
        input_method = st.radio("Log Input Method", ["Text Input", "File Upload (Text/PDF/Image)", "Sample Data"])
        raw_logs = ""
        
        if input_method == "Text Input":
            raw_logs = st.text_area("Paste Security Logs/Alerts", 
                                   height=200,
                                   placeholder="Paste your security logs, alerts, or incident notes here...",
                                   value=st.session_state.raw_logs)
        
        elif input_method == "File Upload (Text/PDF/Image)":
            uploaded_file = st.file_uploader("Upload File (Text, PDF, Image)", type=['txt', 'log', 'json', 'pdf', 'png', 'jpg', 'jpeg'])
            if uploaded_file is not None:
                # Check the file type and extract text accordingly
                file_type = uploaded_file.type
                if file_type in ["text/plain", "application/json"]:
                    # Read as text
                    raw_logs = str(uploaded_file.read(), "utf-8")
                elif file_type in ["application/pdf", "image/png", "image/jpeg"]:
                    # Use OCR processor
                    with st.spinner("Extracting text from file..."):
                        try:
                            raw_logs = ocr_processor.extract_text_from_file(uploaded_file, file_type)
                        except Exception as e:
                            st.error(f"Error during text extraction: {str(e)}")
                            raw_logs = ""
                else:
                    st.error("Unsupported file type")
                    raw_logs = ""
                
                # Display the extracted text for editing
                st.subheader("Extracted Text from File")
                raw_logs = st.text_area("Edit extracted text if needed:", value=raw_logs, height=300)
        
        else:  # Sample Data
            sample_options = st.selectbox("Choose Sample Scenario", [
                "Brute Force Attack",
                "Malware Infection", 
                "Phishing Campaign",
                "Data Exfiltration",
                "Privilege Escalation"
            ])
            
            sample_logs = {
                "Brute Force Attack": """
                [2024-01-15 10:23:45] FAILED LOGIN: User 'admin' from IP 192.168.1.100 (25 attempts in 2 minutes)
                [2024-01-15 10:24:10] ACCOUNT LOCKOUT: User 'admin' temporarily locked
                [2024-01-15 10:25:30] SUCCESSFUL LOGIN: User 'admin' from IP 192.168.1.100 after lockout reset
                [2024-01-15 10:26:15] SUSPICIOUS ACTIVITY: User 'admin' accessing sensitive HR files
                """,
                "Malware Infection": """
                [2024-01-15 14:15:30] MALWARE DETECTED: Trojan:Win32/Agent.XX on workstation WS-108
                [2024-01-15 14:16:45] NETWORK SCAN: WS-108 scanning internal network ports
                [2024-01-15 14:18:20] DATA TRANSFER: 500MB of documents copied from file server
                [2024-01-15 14:20:00] C&C COMMUNICATION: WS-108 connecting to suspicious external IP 185.163.45.22
                """
            }
            raw_logs = sample_logs.get(sample_options, "")
            st.text_area("Sample Logs", raw_logs, height=150)
        
        if raw_logs:
            st.session_state.raw_logs = raw_logs
            
            # Log format selection
            log_format = st.selectbox("Log Format", ["auto", "SIEM", "Firewall", "IDS/IPS", "Custom"])
            
            if st.button("🚀 Analyze with AI", type="primary"):
                with st.spinner("AI is analyzing the incident... This may take a few seconds."):
                    # Analyze with AI
                    incident_data = analyze_incident_with_ai(raw_logs, log_format)
                    
                    if incident_data:
                        # Add metadata
                        incident_data['incident_id'] = f"INC-{int(time.time())}"
                        incident_data['analysis_timestamp'] = datetime.now().isoformat()
                        incident_data['raw_logs_sample'] = raw_logs[:1000] + "..." if len(raw_logs) > 1000 else raw_logs
                        
                        # Store incident
                        st.session_state.incidents.append(incident_data)
                        st.session_state.current_incident = incident_data
                        
                        st.markdown('<div class="success-box">✅ Incident Analysis Complete!</div>', unsafe_allow_html=True)
                        
                        # Display results
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.subheader("📋 Incident Summary")
                            st.write(f"**ID:** {incident_data['incident_id']}")
                            st.write(f"**Severity:** {incident_data['severity_level']}")
                            st.write(f"**Attack Type:** {incident_data['attack_type']}")
                            st.write(f"**Confidence:** {incident_data.get('confidence_score', 'N/A')}")
                        
                        with col2:
                            st.subheader("⏰ Timeline")
                            st.write(f"**Start:** {incident_data['timeline']['start_time']}")
                            st.write(f"**End:** {incident_data['timeline']['end_time']}")
                            st.write(f"**Duration:** {incident_data['timeline']['duration']}")
                        
                        # Visualizations
                        st.subheader("📊 Incident Metrics")
                        fig_gauge, fig_pie = create_visualizations(incident_data)
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            st.plotly_chart(fig_gauge, use_container_width=True)
                        with col2:
                            st.plotly_chart(fig_pie, use_container_width=True)
                        
                        # Mitigation steps
                        st.subheader("🛡️ Recommended Mitigation Steps")
                        for i, step in enumerate(incident_data['mitigation_steps'], 1):
                            st.write(f"{i}. {step}")
                        
                        # Download report
                        report_text = generate_incident_report(incident_data)
                        st.download_button(
                            label="📥 Download Full Report",
                            data=report_text,
                            file_name=f"incident_report_{incident_data['incident_id']}.md",
                            mime="text/markdown"
                        )
                        pdf_bytes = markdown_to_pdf_bytes(report_text)
                        st.download_button(
                            label="📄 Download as PDF",
                            data=pdf_bytes,
                            file_name=f"incident_report_{incident_data['incident_id']}.pdf",
                            mime="application/pdf"
                        )
                    else:
                        st.error("Failed to analyze incident. Please check your logs and try again.")
    
    # Incident Q&A
    elif menu == "💬 Incident Q&A" and st.session_state.current_incident:
        st.markdown('<div class="section-header">AI Incident Investigator</div>', unsafe_allow_html=True)
        
        incident = st.session_state.current_incident
        st.info(f"Currently analyzing: **{incident['incident_id']}** - {incident['attack_type']}")
        
        # Chat interface
        st.subheader("💬 Ask Questions About This Incident")
        
        # Display chat history
        for message in st.session_state.chat_history:
            with st.chat_message(message["role"]):
                st.write(message["content"])
        
        # Chat input
        if prompt := st.chat_input("Ask about the incident, mitigation steps, or technical details..."):
            # Add user message
            st.session_state.chat_history.append({"role": "user", "content": prompt})
            with st.chat_message("user"):
                st.write(prompt)
            
            # Generate AI response
            with st.chat_message("assistant"):
                with st.spinner("Analyzing..."):
                    response = chat_with_incident_data(prompt, incident, st.session_state.chat_history)
                    st.write(response)
            
            # Add AI response to history
            st.session_state.chat_history.append({"role": "assistant", "content": response})
        
        # Quick question suggestions
        st.subheader("💡 Suggested Questions")
        col1, col2, col3 = st.columns(3)
        
        quick_questions = [
            "What's the root cause of this incident?",
            "How should we contain this attack?",
            "What are the key IOCs to monitor?",
            "How can we prevent similar attacks?",
            "What's the business impact?",
            "Who needs to be notified about this?"
        ]
        
        for i, question in enumerate(quick_questions):
            col = [col1, col2, col3][i % 3]
            with col:
                if st.button(question, key=f"q_{i}", use_container_width=True):
                    st.session_state.chat_history.append({"role": "user", "content": question})
                    response = chat_with_incident_data(question, incident, st.session_state.chat_history)
                    st.session_state.chat_history.append({"role": "assistant", "content": response})
                    st.rerun()
        
        if st.button("Clear Chat History"):
            st.session_state.chat_history = []
            st.rerun()
    
    # Reports & Analytics
    elif menu == "📈 Reports & Analytics":
        st.markdown('<div class="section-header">Incident Analytics & Reporting</div>', unsafe_allow_html=True)

        # ========== New: Loaded incidents viewer ==========
        st.subheader("Loaded Incidents (auto-analyzed from logs/)")
        if st.session_state.loaded_incidents:
            ids = sorted(st.session_state.loaded_incidents.keys())
            sel = st.selectbox("Select an incident", ids, key="loaded_incidents_select")
            if sel:
                item = st.session_state.loaded_incidents[sel]
                st.write(f"Source file: {item['file']}  |  Detected format: {item['log_format']}")
                with st.expander("Show raw log"):
                    st.code(item["raw"][:4000])
                report_md = generate_incident_report(item["analysis"])
                st.markdown(report_md)
                st.download_button(
                    "📥 Download Report",
                    report_md,
                    file_name=f"{sel}_report.md",
                    mime="text/markdown"
                )
                pdf_bytes = markdown_to_pdf_bytes(report_md)
                st.download_button(
                    "📄 Download as PDF",
                    pdf_bytes,
                    file_name=f"{sel}_report.pdf",
                    mime="application/pdf"
                )
        else:
            st.info("No files analyzed from logs/ yet. Add files then click 'Rescan logs folder' in the sidebar.")

        st.markdown("---")

        # Existing analytics for session incidents
        if not st.session_state.incidents:
            st.info("No session incidents available for analytics.")
        else:
            st.subheader("📈 Security Metrics (session)")
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                total_incidents = len(st.session_state.incidents)
                st.metric("Total Incidents", total_incidents)
            with col2:
                critical_incidents = len([inc for inc in st.session_state.incidents if inc.get('severity_level') == 'Critical'])
                st.metric("Critical Incidents", critical_incidents)
            with col3:
                avg_confidence = np.mean([inc.get('confidence_score', 0) for inc in st.session_state.incidents])
                st.metric("Average Confidence", f"{avg_confidence:.2f}")
            with col4:
                total_iocs = sum([len(inc.get('indicators_of_compromise', [])) for inc in st.session_state.incidents])
                st.metric("Total IOCs", total_iocs)
            
            # Attack type distribution
            attack_types = {}
            for inc in st.session_state.incidents:
                attack_type = inc.get('attack_type', 'Unknown')
                attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
            
            if attack_types:
                fig_attack = px.bar(
                    x=list(attack_types.keys()),
                    y=list(attack_types.values()),
                    title="Attack Type Distribution (session)",
                    labels={'x': 'Attack Type', 'y': 'Count'}
                )
                st.plotly_chart(fig_attack, use_container_width=True)
            
            # Export all incidents (session)
            if st.button("📊 Export All Session Reports"):
                all_reports = ""
                for inc in st.session_state.incidents:
                    all_reports += generate_incident_report(inc) + "\n" + "="*50 + "\n"
                
                st.download_button(
                    label="📥 Download Comprehensive Report",
                    data=all_reports,
                    file_name=f"comprehensive_incident_report_{datetime.now().strftime('%Y%m%d')}.md",
                    mime="text/markdown"
                )
    
    # Settings
    else:
        st.markdown('<div class="section-header">Application Settings</div>', unsafe_allow_html=True)
        
        st.subheader("AI Configuration")
        st.info("Current AI endpoint: https://genailab.tcs.in")
        
        st.subheader("Data Management")
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("Clear All Incidents", type="secondary"):
                st.session_state.incidents = []
                st.session_state.current_incident = None
                st.session_state.chat_history = []
                st.success("All incident data cleared!")
        
        with col2:
            if st.button("Export Incident Data", type="primary"):
                if st.session_state.incidents:
                    incident_json = json.dumps(st.session_state.incidents, indent=2)
                    st.download_button(
                        label="📥 Download JSON Data",
                        data=incident_json,
                        file_name="incident_data_export.json",
                        mime="application/json"
                    )
        
        st.subheader("About")
        st.write("""
        **CyberSec AI Incident Analysis Platform**
        
        This application uses AI to:
        - Automatically analyze security incidents from raw logs
        - Generate structured incident reports
        - Provide intelligent Q&A capabilities
        - Suggest mitigation steps
        
        Built for cybersecurity teams to accelerate incident response.
        """)

if __name__ == "__main__":
    main()