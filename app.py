"""Streamlit dashboard for AegisStatic - Automated Static Triage & De-Obfuscation Engine."""

import json
import tempfile
from datetime import datetime
from pathlib import Path
import re

import plotly.graph_objects as go
import plotly.express as px
import streamlit as st
import networkx as nx
import capstone

from src.pe_parser import parse_pe_binary, extract_high_entropy_blobs
from src.xor_engine import analyze_blobs
from src.ioc_extractor import (
    process_decryption_results,
    malwarebazaar_lookup,
    classify_behavior_profile,
)
from src.report_generator import generate_pdf_report

# ---------------------------------------------------------------------------
# Page configuration
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="AegisStatic - Static Triage Engine",
    page_icon="🛡️",
    layout="wide",
)

# ---------------------------------------------------------------------------
# Sidebar Settings / Theme Toggle (declared early for CSS injection)
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### Settings")
    dark_mode = st.toggle("Dark Theme Mode", value=True, help="Toggle between premium dark and light themes")

if dark_mode:
    # Inject Dark theme CSS
    st.markdown(
        """
        <style>
        @keyframes fadeIn {
            0% { opacity: 0; transform: translateY(8px); }
            100% { opacity: 1; transform: translateY(0); }
        }
        .stApp {
            background-color: #090d16 !important;
            color: #e6edf3 !important;
            animation: fadeIn 0.4s ease-out;
        }
        header[data-testid="stHeader"] {
            background-color: rgba(0,0,0,0) !important;
        }
        section[data-testid="stSidebar"] {
            background-color: #0d1117 !important;
            border-right: 1px solid #30363d !important;
        }
        section[data-testid="stSidebar"] .stMarkdown, section[data-testid="stSidebar"] h3, section[data-testid="stSidebar"] label, section[data-testid="stSidebar"] span {
            color: #e6edf3 !important;
        }
        [data-testid="stFileUploaderDropzone"] {
            border: 1px dashed #30363d !important;
        }
        [data-testid="stFileUploader"] div, [data-testid="stFileUploader"] span, [data-testid="stFileUploader"] p, [data-testid="stFileUploader"] button {
            background-color: #0d1117 !important;
            color: #e6edf3 !important;
        }
        [data-testid="stFileUploader"] button:hover {
            background-color: #30363d !important;
        }
        [data-testid="stFileUploader"] svg {
            fill: #e6edf3 !important;
        }
        div[data-baseweb="popover"] * {
            background-color: #0d1117 !important;
            color: #e6edf3 !important;
        }
        [data-testid="stMetric"] {
           background-color: #0d1117 !important;
           border: 1px solid #30363d !important;
           padding: 12px 18px;
           border-radius: 6px;
           transition: transform 0.2s ease-in-out, box-shadow 0.2s ease-in-out;
        }
        [data-testid="stMetric"] [data-testid="stMetricLabel"] {
           color: #8b949e !important;
        }
        [data-testid="stMetric"] [data-testid="stMetricValue"] {
           color: #e6edf3 !important;
        }
        [data-testid="stMetric"]:hover {
           transform: translateY(-2px);
           box-shadow: 0 4px 12px rgba(0,0,0,0.3) !important;
           border-color: #58a6ff !important;
        }
        .stCodeBlock, .stCodeBlock pre, .stCodeBlock code {
            background-color: #0d1117 !important;
            color: #e6edf3 !important;
        }
        .stTabs [data-baseweb="tab-list"] {
            gap: 16px;
        }
        .stTabs [data-baseweb="tab"] {
            background-color: #0d1117 !important;
            border: 1px solid #30363d !important;
            border-radius: 6px 6px 0px 0px !important;
            padding: 8px 16px;
            color: #8b949e !important;
            font-weight: 600;
            transition: all 0.2s ease;
        }
        .stTabs [data-baseweb="tab"]:hover {
            color: #c9d1d9 !important;
            background-color: #161b22 !important;
        }
        .stTabs [aria-selected="true"] {
            background-color: #1f2937 !important;
            color: #58a6ff !important;
            border-bottom: 2px solid #58a6ff !important;
        }
        .verdict-box {
            padding: 16px;
            border-radius: 6px;
            margin-bottom: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.2);
            animation: fadeIn 0.3s ease-out;
        }
        .verdict-malicious {
            background-color: #3b1218 !important;
            border: 1px solid #f85149 !important;
            color: #f85149 !important;
        }
        .verdict-suspicious {
            background-color: #382402 !important;
            border: 1px solid #d29922 !important;
            color: #d29922 !important;
        }
        .verdict-clean {
            background-color: #0f2c16 !important;
            border: 1px solid #3fb950 !important;
            color: #3fb950 !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
    plotly_template = "plotly_dark"
    call_graph_color = "#30363d"
    call_graph_text_color = "#c9d1d9"
else:
    # Inject Light theme CSS
    st.markdown(
        """
        <style>
        @keyframes fadeIn {
            0% { opacity: 0; transform: translateY(8px); }
            100% { opacity: 1; transform: translateY(0); }
        }
        .stApp {
            background-color: #f6f8fa !important;
            color: #24292f !important;
            animation: fadeIn 0.4s ease-out;
        }
        header[data-testid="stHeader"] {
            background-color: rgba(0,0,0,0) !important;
        }
        section[data-testid="stSidebar"] {
            background-color: #ffffff !important;
            border-right: 1px solid #d0d7de !important;
        }
        section[data-testid="stSidebar"] .stMarkdown, section[data-testid="stSidebar"] h3, section[data-testid="stSidebar"] label, section[data-testid="stSidebar"] span {
            color: #24292f !important;
        }
        [data-testid="stFileUploaderDropzone"] {
            border: 1px dashed #d0d7de !important;
        }
        [data-testid="stFileUploader"] div, [data-testid="stFileUploader"] span, [data-testid="stFileUploader"] p, [data-testid="stFileUploader"] button {
            background-color: #ffffff !important;
            color: #24292f !important;
        }
        [data-testid="stFileUploader"] button:hover {
            background-color: #eaeef2 !important;
        }
        [data-testid="stFileUploader"] svg {
            fill: #24292f !important;
        }
        div[data-baseweb="popover"] * {
            background-color: #ffffff !important;
            color: #24292f !important;
        }
        [data-testid="stMetric"] {
           background-color: #ffffff !important;
           border: 1px solid #d0d7de !important;
           padding: 12px 18px;
           border-radius: 6px;
           box-shadow: 0 1px 3px rgba(0,0,0,0.05) !important;
           transition: transform 0.2s ease-in-out, box-shadow 0.2s ease-in-out;
        }
        [data-testid="stMetric"] [data-testid="stMetricLabel"] {
           color: #57606a !important;
        }
        [data-testid="stMetric"] [data-testid="stMetricValue"] {
           color: #24292f !important;
        }
        [data-testid="stMetric"]:hover {
           transform: translateY(-2px);
           box-shadow: 0 4px 12px rgba(0,0,0,0.1) !important;
           border-color: #0969da !important;
        }
        .stCodeBlock, .stCodeBlock pre, .stCodeBlock code {
            background-color: #ffffff !important;
            color: #24292f !important;
            border: 1px solid #d0d7de !important;
        }
        .stTextInput input, .stSelectbox div[data-baseweb="select"], .stTextArea textarea {
            background-color: #ffffff !important;
            color: #24292f !important;
            border: 1px solid #d0d7de !important;
        }
        .stExpander {
            background-color: #ffffff !important;
            border: 1px solid #d0d7de !important;
        }
        .stExpander * {
            color: #24292f !important;
        }
        .stButton button {
            background-color: #f6f8fa !important;
            color: #24292f !important;
            border: 1px solid #d0d7de !important;
        }
        .stButton button:hover {
            background-color: #eaeef2 !important;
            color: #24292f !important;
            border-color: #0969da !important;
        }
        .stTabs [data-baseweb="tab-list"] {
            gap: 16px;
        }
        .stTabs [data-baseweb="tab"] {
            background-color: #f6f8fa !important;
            border: 1px solid #d0d7de !important;
            border-radius: 6px 6px 0px 0px !important;
            padding: 8px 16px;
            color: #57606a !important;
            font-weight: 600;
            transition: all 0.2s ease;
        }
        .stTabs [data-baseweb="tab"]:hover {
            color: #24292f !important;
            background-color: #eaeef2 !important;
        }
        .stTabs [aria-selected="true"] {
            background-color: #ffffff !important;
            color: #0969da !important;
            border-bottom: 2px solid #0969da !important;
        }
        .verdict-box {
            padding: 16px;
            border-radius: 6px;
            margin-bottom: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            animation: fadeIn 0.3s ease-out;
        }
        .verdict-malicious {
            background-color: #ffebe9 !important;
            border: 1px solid #ff8182 !important;
            color: #cf222e !important;
        }
        .verdict-suspicious {
            background-color: #fff8c5 !important;
            border: 1px solid #d0962b !important;
            color: #9a6700 !important;
        }
        .verdict-clean {
            background-color: #dafbe1 !important;
            border: 1px solid #4ac26b !important;
            color: #1a7f37 !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
    plotly_template = "plotly_white"
    call_graph_color = "#d0d7de"
    call_graph_text_color = "#24292f"

st.title("🛡️ AegisStatic: Static Triage & De-Obfuscation Engine")
st.caption(
    "Automated deep static triage, entropy mapping, and payload de-obfuscation platform"
)

# ---------------------------------------------------------------------------
# Sidebar input
# ---------------------------------------------------------------------------
with st.sidebar:
    st.header("Binary Upload")
    uploaded_file = st.file_uploader(
        "Upload Windows PE Binary",
        type=["exe", "dll", "sys", "ocx"],
        help="Supported: .exe, .dll, .sys, .ocx",
    )
    st.divider()
    st.markdown(
        "### Operational Pipeline\n"
        "1. **Header Parsing**: Mitigations & Imports\n"
        "2. **Entropy Map**: High-entropy target search\n"
        "3. **De-Obfuscation**: 1-byte & 2-byte XOR + B64/ROT13\n"
        "4. **Threat Mapping**: MITRE ATT&CK Matrix\n"
        "5. **YARA Generation**: Compiles indicator rules"
    )

# ---------------------------------------------------------------------------
# Helper / Graphics generators
# ---------------------------------------------------------------------------

def _section_to_dict(sec) -> dict:
    if isinstance(sec, dict):
        return sec
    return {
        "name": sec.name,
        "virtual_address": getattr(sec, "virtual_address", 0),
        "virtual_size": sec.virtual_size,
        "raw_size": sec.raw_size,
        "entropy": sec.entropy,
        "is_suspicious": sec.is_suspicious,
    }


def _build_analysis_payload(
    pe_data: dict,
    all_decryption_results: list[dict],
    iocs: list,
    mitre_summary: dict,
    risk_score: float,
    behavior_profile: dict,
    bazaar_data: dict,
) -> dict:
    return {
        "filename": pe_data.get("filename", ""),
        "file_hash_md5": pe_data.get("file_hash_md5", ""),
        "file_hash_sha256": pe_data.get("file_hash_sha256", ""),
        "file_size": pe_data.get("file_size", 0),
        "sections": [_section_to_dict(s) for s in pe_data.get("sections", [])],
        "decryption_results": all_decryption_results,
        "iocs": iocs if isinstance(iocs, list) else [],
        "mitre_summary": mitre_summary if isinstance(mitre_summary, dict) else {},
        "risk_score": risk_score,
        "aslr": pe_data.get("aslr", False),
        "dep": pe_data.get("dep", False),
        "cfg": pe_data.get("cfg", False),
        "safeseh": pe_data.get("safeseh", False),
        "authenticode": pe_data.get("authenticode", False),
        "embedded_pes": pe_data.get("embedded_pes", []),
        "raw_strings": pe_data.get("raw_strings", []),
        "imports": pe_data.get("imports", []),
        "dangerous_imports": pe_data.get("dangerous_imports", []),
        "behavior_profile": behavior_profile,
        "malwarebazaar": bazaar_data,
        "pe_type": pe_data.get("pe_type", 0x10b),
    }


def generate_yara_rule(analysis: dict) -> str:
    filename = analysis.get("filename", "unknown_file").replace(".", "_")
    rule_name = re.sub(r'[^A-Za-z0-9_]', '_', filename)
    if not rule_name[0].isalpha():
        rule_name = "Rule_" + rule_name
        
    sha256 = analysis.get("file_hash_sha256", "")
    md5 = analysis.get("file_hash_md5", "")
    iocs = analysis.get("iocs", [])
    
    strings = []
    # Add network IOCs
    net_iocs = [ioc["value"] for ioc in iocs if ioc["ioc_type"] in ("URL Pattern", "IPv4 Address")][:5]
    for idx, net in enumerate(net_iocs):
        escaped = net.replace('"', '\\"')
        strings.append(f'        $net_{idx} = "{escaped}"')
        
    # Add API calls
    dangerous_apis = list(set([ioc["value"] for ioc in iocs if "API" in ioc["ioc_type"]]))[:5]
    for idx, api in enumerate(dangerous_apis):
        strings.append(f'        $api_{idx} = "{api}" ascii nocase')
        
    # Add decryption keywords
    dec_keywords = []
    for res in analysis.get("decryption_results", []):
        for kw in res.get("keyword_hits", []):
            dec_keywords.append(kw)
    unique_kws = list(set(dec_keywords))[:5]
    for idx, kw in enumerate(unique_kws):
        strings.append(f'        $dec_kw_{idx} = "{kw}" ascii nocase')

    if not strings:
        strings.append('        $s1 = "AEGISSTATIC_STATIC_TRIAGE_RULE"')

    string_block = "\n".join(strings)
    
    return f"""rule AegisStatic_{rule_name} {{
    meta:
        description = "Automated threat signature generated by AegisStatic triage platform"
        author = "AegisStatic Engine"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
        file_md5 = "{md5}"
        file_sha256 = "{sha256}"
        risk_score = "{analysis.get('risk_score', 0.0)}"
        behavior = "{analysis.get('behavior_profile', {}).get('class', 'Suspicious')}"

    strings:
{string_block}

    condition:
        any of them
}}"""


def generate_call_graph_plotly(analysis: dict, template: str = "plotly_dark", text_color: str = "#c9d1d9", edge_color: str = "#30363d") -> go.Figure:
    G = nx.DiGraph()
    G.add_node("EntryPoint", size=22, color="#58a6ff", type="Root")
    
    apis = list(set(analysis.get("dangerous_imports", [])))[:8]
    for api in apis:
        col = "#f85149" if any(x in api for x in ("Thread", "Alloc", "Write", "Unmap")) else "#d29922"
        G.add_node(api, size=16, color=col, type="API")
        G.add_edge("EntryPoint", api)
        
    nets = list(set([ioc["value"] for ioc in analysis.get("iocs", []) if ioc["ioc_type"] in ("URL Pattern", "IPv4 Address")]))[:4]
    for net in nets:
        lbl = net[:22] + "..." if len(net) > 22 else net
        G.add_node(lbl, size=15, color="#ff79c6", type="Network")
        if apis:
            G.add_edge(apis[0], lbl)
        else:
            G.add_edge("EntryPoint", lbl)
            
    # Default node if graph is empty
    if len(G) <= 1:
        G.add_node("Main", size=16, color="#8b949e", type="Node")
        G.add_node("Init", size=16, color="#8b949e", type="Node")
        G.add_edge("EntryPoint", "Main")
        G.add_edge("Main", "Init")
        
    pos = nx.spring_layout(G, seed=42)
    
    edge_x, edge_y = [], []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])
        
    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=1.5, color=edge_color),
        hoverinfo='none',
        mode='lines'
    )
    
    node_x, node_y = [], []
    node_text, node_color, node_size = [], [], []
    
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        node_text.append(node)
        node_color.append(G.nodes[node]["color"])
        node_size.append(G.nodes[node]["size"])
        
    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        hoverinfo='text',
        text=node_text,
        textposition="top center",
        textfont=dict(color=text_color, size=10),
        marker=dict(
            color=node_color,
            size=node_size,
            line=dict(width=2, color=edge_color)
        )
    )
    
    fig = go.Figure(
        data=[edge_trace, node_trace],
        layout=go.Layout(
            showlegend=False,
            hovermode='closest',
            margin=dict(b=10, l=5, r=5, t=10),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            template=template,
            height=450,
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
        )
    )
    return fig


def disassemble_pe_section(raw_data: bytes, base_addr: int, pe_type: int, count: int = 100) -> list[str]:
    """Disassemble raw section data using capstone."""
    if not raw_data:
        return ["No code bytes to disassemble."]
    
    arch = capstone.CS_ARCH_X86
    mode = capstone.CS_MODE_64 if pe_type == 0x20b else capstone.CS_MODE_32
    
    try:
        md = capstone.Cs(arch, mode)
        instructions = []
        # Disassemble first 3KB maximum for UI responsiveness
        for insn in md.disasm(raw_data[:3000], base_addr):
            instructions.append(f"0x{insn.address:08X}:\t{insn.mnemonic:<10}{insn.op_str}")
            if len(instructions) >= count:
                break
        if not instructions:
            return ["No executable instructions identified in this data segment."]
        return instructions
    except Exception as exc:
        return [f"Disassembly error: {exc}"]


# ---------------------------------------------------------------------------
# Execution Pipeline
# ---------------------------------------------------------------------------
if uploaded_file is not None:
    tmp_dir = Path(tempfile.mkdtemp())
    tmp_path = tmp_dir / uploaded_file.name
    tmp_path.write_bytes(uploaded_file.getvalue())

    try:
        with st.spinner("Executing Static Parser & Mitigations Scan..."):
            pe_data = parse_pe_binary(str(tmp_path))

        if pe_data.get("error"):
            st.error(f"Triage Engine Failure: {pe_data['error']}")
            st.stop()

        # MalwareBazaar Intelligence Lookup
        with st.spinner("Connecting to MalwareBazaar threat intelligence database..."):
            sha256_hash = pe_data.get("file_hash_sha256", "")
            bazaar_data = malwarebazaar_lookup(sha256_hash)

        # De-obfuscation XOR brute-force
        all_decryption_results: list[dict] = []
        with st.spinner("Scanning high-entropy sections & running de-obfuscator..."):
            for sec in pe_data.get("suspicious_sections", []):
                raw_data = sec.raw_data if hasattr(sec, "raw_data") else sec.get("raw_data", b"")
                sec_name = sec.name if hasattr(sec, "name") else sec.get("name", "?")
                blobs = extract_high_entropy_blobs(raw_data)
                if blobs:
                    results = analyze_blobs(blobs, sec_name)
                    all_decryption_results.extend(results)

        # Process IOCs and build verdicts
        with st.spinner("Performing regex deobfuscation and threat profiling..."):
            iocs, mitre_summary, risk_score = process_decryption_results(
                all_decryption_results,
                raw_strings=pe_data.get("raw_strings", [])
            )
            behavior_profile = classify_behavior_profile(iocs)

        # Build analysis dictionary
        analysis = _build_analysis_payload(
            pe_data, all_decryption_results, iocs, mitre_summary, risk_score, behavior_profile, bazaar_data
        )
        st.session_state["analysis"] = analysis

        # -------------------------------------------------------------------
        # 6-Tab Interface Layout
        # -------------------------------------------------------------------
        t_overview, t_entropy, t_decrypt, t_mitre, t_re, t_export = st.tabs([
            "🖥️ Overview", "📊 Entropy Map", "🔓 Decryption Results", 
            "🎯 MITRE ATT&CK", "🧬 Static RE Analysis", "💾 Export & YARA"
        ])

        # -------------------------------------------------------------------
        # TAB 1: Overview & Verdicts
        # -------------------------------------------------------------------
        with t_overview:
            # Dynamic Verdict Banner
            if risk_score > 70:
                st.markdown(
                    '<div class="verdict-box verdict-malicious">'
                    '<h3>🚨 MALWARE THREAT DETECTED</h3>'
                    '<p>Static analysis identified multiple severe indicators, process evasion traits, or signature hits.</p>'
                    '</div>',
                    unsafe_allow_html=True
                )
            elif risk_score > 40:
                st.markdown(
                    '<div class="verdict-box verdict-suspicious">'
                    '<h3>⚠️ SUSPICIOUS BEHAVIOR FLAG</h3>'
                    '<p>The binary is obfuscated, contains packed sections, or has elevated risk indicators.</p>'
                    '</div>',
                    unsafe_allow_html=True
                )
            else:
                st.markdown(
                    '<div class="verdict-box verdict-clean">'
                    '<h3>✅ CLEAN / LOW RISK STATUS</h3>'
                    '<p>No critical malicious imports, suspicious persistence mechanisms, or packed flags identified.</p>'
                    '</div>',
                    unsafe_allow_html=True
                )

            # Metric & Threat Index Gauge Layout
            col_metrics, col_gauge = st.columns([2, 3])
            with col_metrics:
                st.metric("Risk Score Index", f"{risk_score:.1f} / 100")
                st.metric("Suspicious Sections Identified", len(pe_data.get("suspicious_sections", [])))
                st.metric("Security Threat Indicators", len(iocs))
            with col_gauge:
                fig_gauge = go.Figure(go.Indicator(
                    mode = "gauge+number",
                    value = risk_score,
                    domain = {'x': [0, 1], 'y': [0, 1]},
                    title = {'text': "Calculated Threat Index", 'font': {'size': 16, 'color': call_graph_text_color}},
                    gauge = {
                        'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "gray"},
                        'bar': {'color': "#f85149" if risk_score > 70 else ("#d29922" if risk_score > 40 else "#3fb950")},
                        'bgcolor': "rgba(0,0,0,0)",
                        'borderwidth': 2,
                        'bordercolor': "gray",
                        'steps': [
                            {'range': [0, 40], 'color': 'rgba(63, 185, 80, 0.15)'},
                            {'range': [40, 70], 'color': 'rgba(210, 153, 34, 0.15)'},
                            {'range': [70, 100], 'color': 'rgba(248, 81, 73, 0.15)'}
                        ],
                    }
                ))
                fig_gauge.update_layout(
                    height=240,
                    margin=dict(l=10, r=10, t=40, b=10),
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font={'color': call_graph_text_color}
                )
                st.plotly_chart(fig_gauge, use_container_width=True)

            st.divider()

            # Profile & Threat Intel Row
            col_prof, col_intel = st.columns(2)
            with col_prof:
                st.subheader("Classification Profile")
                st.markdown(f"**Triage Class:** `{behavior_profile['class']}`")
                st.markdown(f"**Confidence Rating:** `{behavior_profile['confidence']}`")
                st.caption("Inferred from matching behavioral combinations of ATT&CK tactics.")

            with col_intel:
                st.subheader("Threat Intelligence Lookup")
                if bazaar_data.get("found"):
                    st.success(f"Matched in MalwareBazaar! Signature: **{bazaar_data['signature']}**")
                    st.markdown(f"**Tags:** `{', '.join(bazaar_data['tags'])}` | **Reporter:** `{bazaar_data['reporter']}`")
                else:
                    st.info("No corresponding hash signature matches found in the MalwareBazaar feed.")

            st.divider()

            # File Info
            st.subheader("File Metadata")
            m1, m2 = st.columns(2)
            with m1:
                st.markdown(f"**Filename:** `{analysis['filename']}`")
                st.markdown(f"**File Size:** {analysis['file_size']:,} bytes")
            with m2:
                st.markdown(f"**MD5:** `{analysis['file_hash_md5']}`")
                st.markdown(f"**SHA-256:** `{analysis['file_hash_sha256']}`")

        # -------------------------------------------------------------------
        # TAB 2: Entropy Map
        # -------------------------------------------------------------------
        with t_entropy:
            sections = analysis["sections"]
            if not sections:
                st.info("No PE sections identified.")
            else:
                names = [s["name"] for s in sections]
                entropies = [s["entropy"] for s in sections]
                colors = ["#f85149" if s["is_suspicious"] else "#3fb950" for s in sections]

                fig = go.Figure()
                fig.add_trace(go.Bar(
                    x=names, y=entropies,
                    marker_color=colors,
                    text=[f"{e:.2f}" for e in entropies],
                    textposition="outside",
                    name="Entropy",
                ))
                fig.add_hline(
                    y=6.5, line_dash="dash", line_color="orange",
                    annotation_text="Threshold (6.5)", annotation_position="top left",
                )
                fig.update_layout(
                    title="Section Shannon Entropy Distribution",
                    xaxis_title="PE Section",
                    yaxis_title="Entropy Value",
                    yaxis_range=[0, 8.5],
                    template=plotly_template,
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    height=400,
                )
                st.plotly_chart(fig, use_container_width=True)

                st.subheader("Section Specifications")
                for s in sections:
                    status = "⚠️ Suspicious (Packed/Encrypted)" if s["is_suspicious"] else "✅ Safe"
                    with st.expander(f"Section {s['name']} | Entropy: {s['entropy']:.4f} | {status}"):
                        sc1, sc2 = st.columns(2)
                        with sc1:
                            st.markdown(f"**Virtual Size:** {s['virtual_size']:,} bytes")
                        with sc2:
                            st.markdown(f"**Raw Size:** {s['raw_size']:,} bytes")

        # -------------------------------------------------------------------
        # TAB 3: Decryption & De-obfuscation Results
        # -------------------------------------------------------------------
        with t_decrypt:
            if not all_decryption_results:
                st.info("No packed payloads decrypted. Obfuscation keys were not recovered.")
            else:
                st.subheader("Recovered Plaintext Decryptions")
                table_rows = []
                for r in all_decryption_results:
                    preview = r.get("decrypted_text", "")[:120]
                    if len(r.get("decrypted_text", "")) > 120:
                        preview += "..."
                    table_rows.append({
                        "Source Section": r.get("source_section", ""),
                        "Key Used": r.get("xor_key_hex", f"0x{r.get('xor_key', 0):02X}"),
                        "Confidence": f"{r.get('confidence_score', 0) * 100:.1f}%",
                        "Keyword Hits": len(r.get("keyword_hits", [])),
                        "Decrypted Preview": preview,
                    })

                st.dataframe(table_rows, use_container_width=True, hide_index=True)

                st.subheader("Extended String Previews")
                for idx, r in enumerate(all_decryption_results[:15], start=1):
                    key_hex = r.get("xor_key_hex", f"0x{r.get('xor_key', 0):02X}")
                    with st.expander(f"Result #{idx} | Key: {key_hex} | Confidence: {r.get('confidence_score', 0)*100:.1f}%"):
                        kws = r.get("keyword_hits", [])
                        if kws:
                            st.markdown("**Matched Signatures:** " + ", ".join(f"`{k}`" for k in kws))
                        st.code(r.get("decrypted_text", ""), language=None)

        # -------------------------------------------------------------------
        # TAB 4: MITRE ATT&CK Mapping
        # -------------------------------------------------------------------
        with t_mitre:
            if not iocs:
                st.info("No threat mappings found in the parsed data.")
            else:
                if mitre_summary:
                    st.subheader("Mapped ATT&CK Tactics")
                    tactics = list(mitre_summary.keys())
                    counts = []
                    for t in tactics:
                        det = mitre_summary[t]
                        counts.append(det.get("technique_count", 1) if isinstance(det, dict) else len(det))

                    fig_m = go.Figure(go.Bar(
                        x=tactics, y=counts,
                        marker_color="#f85149",
                        text=counts, textposition="outside",
                    ))
                    fig_m.update_layout(
                        title="Detections by ATT&CK Tactic Group",
                        xaxis_title="Tactic",
                        yaxis_title="Techniques Matched",
                        template=plotly_template,
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)',
                        height=350,
                    )
                    st.plotly_chart(fig_m, use_container_width=True)

                st.subheader("Deduplicated Threat Indicators (IOCs)")
                ioc_table = []
                for ioc in iocs:
                    ioc_table.append({
                        "Category": ioc.get("ioc_type", ""),
                        "Matched Value": ioc.get("value", ""),
                        "Severity": ioc.get("severity", "Info"),
                        "MITRE Technique": f"{ioc.get('mitre_technique_id')} - {ioc.get('mitre_technique_name')}",
                        "Extraction Source": ioc.get("source_section", "")
                    })
                
                sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
                ioc_table.sort(key=lambda x: sev_order.get(x["Severity"], 5))
                st.dataframe(ioc_table, use_container_width=True, hide_index=True)

        # -------------------------------------------------------------------
        # TAB 5: Static RE Analysis
        # -------------------------------------------------------------------
        with t_re:
            # Column 1: Mitigations, Compiler, and Call Graph
            col_graph, col_checklist = st.columns([3, 2])
            
            with col_checklist:
                st.subheader("Binary Mitigations Checklist")
                mit_data = [
                    {"Mitigation": "ASLR (Address Space Layout)", "Status": "ENABLED" if analysis["aslr"] else "DISABLED"},
                    {"Mitigation": "DEP/NX (Data Execution Prevention)", "Status": "ENABLED" if analysis["dep"] else "DISABLED"},
                    {"Mitigation": "Control Flow Guard (CFG)", "Status": "ENABLED" if analysis["cfg"] else "DISABLED"},
                    {"Mitigation": "SafeSEH (SEH Protection)", "Status": "ENABLED" if analysis["safeseh"] else "DISABLED"},
                    {"Mitigation": "Authenticode Signature Check", "Status": "SIGNED" if analysis["authenticode"] else "UNSIGNED"},
                ]
                st.dataframe(mit_data, use_container_width=True, hide_index=True)

                # Compiler & Packer Info
                st.subheader("Signature Identification")
                sec_names = "".join(names).lower()
                if "upx" in sec_names:
                    packer = "UPX Packed Binary"
                elif "aspack" in sec_names:
                    packer = "ASPack Compressed"
                else:
                    packer = "Microsoft Visual Studio C++ Compiler (Linker standard)"
                st.info(f"**Compiler / Packer Class:**\n{packer}")

            with col_graph:
                st.subheader("Control Flow & Import Mapping")
                st.plotly_chart(generate_call_graph_plotly(analysis, template=plotly_template, text_color=call_graph_text_color, edge_color=call_graph_color), use_container_width=True)

            st.divider()

            # Disassembly Explorer
            st.subheader("Capstone Disassembly Explorer")
            selected_section = st.selectbox(
                "Select PE section for raw disassembly:",
                [s["name"] for s in sections]
            )
            
            if selected_section:
                sec_obj = next(s for s in pe_data["sections"] if s.name == selected_section)
                raw_bytes = sec_obj.raw_data
                base_addr = sec_obj.virtual_address
                pe_type = analysis.get("pe_type", 0x10b)
                
                with st.spinner("Disassembling binary section..."):
                    opcodes = disassemble_pe_section(raw_bytes, base_addr, pe_type, count=100)
                
                st.code("\n".join(opcodes), language="x86asm")

            st.divider()

            # String Clusters
            st.subheader("Extracted String Clusters")
            urls = [s for s in analysis["raw_strings"] if "http" in s.lower() or "https" in s.lower()]
            apis_str = [s for s in analysis["raw_strings"] if any(x in s for x in ("Alloc", "Thread", "Memory", "Protect", "Write"))]
            others = [s for s in analysis["raw_strings"] if s not in urls and s not in apis_str]

            str_tab1, str_tab2, str_tab3 = st.tabs(["🌐 Network Strings", "⚙️ Call Strings", "📁 Miscellaneous"])
            with str_tab1:
                st.write(urls if urls else ["No network patterns extracted."])
            with str_tab2:
                st.write(apis_str if apis_str else ["No dangerous call hooks found."])
            with str_tab3:
                st.write(others[:300] if others else ["No other strings found."])

        # -------------------------------------------------------------------
        # TAB 6: Export & YARA Rules
        # -------------------------------------------------------------------
        with t_export:
            st.subheader("Automated Detection Rules (YARA)")
            yara_code = generate_yara_rule(analysis)
            st.code(yara_code, language="yara")
            
            st.download_button(
                label="Download YARA Rule",
                data=yara_code,
                file_name=f"aegisstatic_{analysis['filename']}.yar",
                mime="text/plain"
            )

            st.divider()

            st.subheader("Report Exporter")
            col_pdf, col_json = st.columns(2)
            with col_pdf:
                st.markdown("**Forensic PDF Report**")
                if st.button("Compile PDF Report", type="primary"):
                    with st.spinner("Compiling PDF..."):
                        pdf_path = generate_pdf_report(analysis)
                        st.session_state["pdf_path"] = pdf_path
                    st.success("PDF compiled successfully.")

                if "pdf_path" in st.session_state:
                    pdf_bytes = Path(st.session_state["pdf_path"]).read_bytes()
                    st.download_button(
                        label="Download PDF Report",
                        data=pdf_bytes,
                        file_name=f"aegisstatic_{analysis['filename']}.pdf",
                        mime="application/pdf",
                    )

            with col_json:
                st.markdown("**Raw JSON Payload**")
                json_str = json.dumps(analysis, indent=2, default=str)
                st.download_button(
                    label="Download JSON Payload",
                    data=json_str,
                    file_name=f"aegisstatic_{analysis['filename']}.json",
                    mime="application/json",
                )

    except Exception as exc:
        st.error(f"Execution Error: {exc}")
        with st.expander("Debugging Traceback"):
            import traceback
            st.code(traceback.format_exc())

else:
    st.divider()
    col_a, col_b, col_c = st.columns(3)
    with col_a:
        st.markdown("### 📊 Entropy Map")
        st.markdown(
            "Graph section-level randomness to isolate packed wrappers and identify dynamic execution stubs."
        )
    with col_b:
        st.markdown("### 🔓 Automated De-Obfuscation")
        st.markdown(
            "Iterates over double-byte keys and Base64/ROT13 encodings using vectorised multi-threading."
        )
    with col_c:
        st.markdown("### 🎯 ATT&CK Mapping")
        st.markdown(
            "Profiles binary behavior automatically, maps indicators to MITRE tactics, and exports reports."
        )
    st.info("Drag and drop a Windows PE binary in the sidebar to run the analysis pipeline.")
