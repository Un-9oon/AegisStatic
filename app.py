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
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap');
        
        @keyframes fadeIn {
            0% { opacity: 0; transform: translateY(8px); }
            100% { opacity: 1; transform: translateY(0); }
        }
        
        html, body, [class*="css"], .stApp, section[data-testid="stSidebar"] {
            font-family: 'Plus Jakarta Sans', sans-serif !important;
        }
        
        .stApp {
            background: radial-gradient(circle at 50% 50%, #0f172a 0%, #030712 100%) !important;
            color: #f1f5f9 !important;
            animation: fadeIn 0.4s ease-out;
        }
        
        header[data-testid="stHeader"] {
            background-color: rgba(0,0,0,0) !important;
        }
        
        section[data-testid="stSidebar"] {
            background-color: #0b0f19 !important;
            border-right: 1px solid rgba(255, 255, 255, 0.05) !important;
        }
        
        section[data-testid="stSidebar"] .stMarkdown, section[data-testid="stSidebar"] h3, section[data-testid="stSidebar"] label, section[data-testid="stSidebar"] span {
            color: #f1f5f9 !important;
        }
        
        [data-testid="stFileUploader"] {
            background: rgba(15, 23, 42, 0.5) !important;
            border: 1px solid rgba(255, 255, 255, 0.05) !important;
            border-radius: 12px !important;
            padding: 16px !important;
        }
        
        [data-testid="stFileUploaderDropzone"] {
            border: 2px dashed rgba(99, 102, 241, 0.4) !important;
            border-radius: 12px !important;
            background-color: rgba(15, 23, 42, 0.4) !important;
            transition: all 0.3s ease;
        }
        
        [data-testid="stFileUploaderDropzone"]:hover {
            border-color: #06b6d4 !important;
            box-shadow: 0 0 15px rgba(6, 182, 212, 0.15) !important;
        }
        
        [data-testid="stFileUploaderDropzone"] * {
            color: #94a3b8 !important;
        }
        
        [data-testid="stFileUploaderDropzone"] button {
            background-color: #4f46e5 !important;
            color: #ffffff !important;
            border: none !important;
            padding: 8px 16px !important;
            border-radius: 8px !important;
            font-weight: 600 !important;
        }
        
        [data-testid="stFileUploaderDropzone"] button:hover {
            background-color: #4338ca !important;
        }
        
        [data-testid="stUploadedFile"], [data-testid="stUploadedFile"] > div {
            background-color: rgba(15, 23, 42, 0.8) !important;
            border: 1px solid rgba(99, 102, 241, 0.2) !important;
            border-radius: 8px !important;
            color: #cbd5e1 !important;
        }
        
        [data-testid="stUploadedFile"] span, [data-testid="stUploadedFile"] p, [data-testid="stUploadedFile"] small, [data-testid="stUploadedFile"] div {
            color: #cbd5e1 !important;
        }
        
        [data-testid="stUploadedFile"] svg {
            fill: #cbd5e1 !important;
        }
        
        div[data-baseweb="popover"] * {
            background-color: #0b0f19 !important;
            color: #f1f5f9 !important;
        }
        
        .main-header {
            display: flex;
            align-items: center;
            gap: 20px;
            padding: 24px 32px;
            background: linear-gradient(135deg, rgba(15, 23, 42, 0.6), rgba(30, 41, 59, 0.4));
            border-radius: 16px;
            border: 1px solid rgba(99, 102, 241, 0.15);
            margin-bottom: 30px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
        }
        
        .header-logo {
            font-size: 40px;
        }
        
        .gradient-title {
            font-size: 36px;
            font-weight: 800;
            margin: 0;
            letter-spacing: -0.5px;
            background: linear-gradient(135deg, #818cf8, #22d3ee, #34d399);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .subtitle {
            font-size: 14px;
            color: #94a3b8;
            margin: 6px 0 0 0;
            font-weight: 500;
        }
        
        .custom-metrics-grid {
            display: flex;
            flex-direction: column;
            gap: 16px;
        }
        
        .metric-card {
            display: flex;
            align-items: center;
            gap: 16px;
            padding: 16px 20px;
            background: rgba(15, 23, 42, 0.5);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 12px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        .metric-card:hover {
            transform: translateY(-3px) scale(1.02);
            border-color: rgba(99, 102, 241, 0.4);
            box-shadow: 0 8px 25px rgba(99, 102, 241, 0.15);
        }
        
        .metric-icon {
            font-size: 32px;
            display: flex;
            align-items: center;
            justify-content: center;
            width: 54px;
            height: 54px;
            background: rgba(99, 102, 241, 0.1);
            border-radius: 10px;
            border: 1px solid rgba(99, 102, 241, 0.2);
        }
        
        .metric-content {
            display: flex;
            flex-direction: column;
            flex-grow: 1;
        }
        
        .metric-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            color: #94a3b8;
            font-weight: 600;
        }
        
        .metric-value {
            font-size: 26px;
            font-weight: 800;
            color: #ffffff;
            line-height: 1.2;
            margin: 4px 0;
        }
        
        .metric-max {
            font-size: 14px;
            color: #64748b;
            font-weight: 500;
        }
        
        .metric-progress-bar {
            width: 100%;
            height: 6px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 4px;
            overflow: hidden;
            margin-top: 6px;
        }
        
        .progress-fill {
            height: 100%;
            border-radius: 4px;
        }
        
        .metric-desc {
            font-size: 11px;
            color: #64748b;
            margin-top: 2px;
        }
        
        .stCodeBlock, .stCodeBlock pre, .stCodeBlock code {
            background-color: #0b0f19 !important;
            color: #cbd5e1 !important;
            border: 1px solid rgba(255, 255, 255, 0.05) !important;
            border-radius: 8px !important;
        }
        
        .stTabs [data-baseweb="tab-list"] {
            border-bottom: none !important;
            padding: 4px;
            background: rgba(15, 23, 42, 0.4);
            border-radius: 12px;
            border: 1px solid rgba(255, 255, 255, 0.05);
            gap: 8px;
        }
        
        .stTabs [data-baseweb="tab"] {
            padding: 10px 20px !important;
            font-weight: 700 !important;
            letter-spacing: 0.5px;
            color: #94a3b8 !important;
            background: transparent !important;
            border: none !important;
            border-radius: 8px !important;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
        }
        
        .stTabs [aria-selected="true"] {
            background: linear-gradient(135deg, rgba(99, 102, 241, 0.15), rgba(6, 182, 212, 0.15)) !important;
            color: #818cf8 !important;
            border: 1px solid rgba(99, 102, 241, 0.3) !important;
            box-shadow: 0 4px 15px rgba(99, 102, 241, 0.1) !important;
        }
        
        .stTabs [data-baseweb="tab"]:hover {
            color: #e2e8f0 !important;
        }
        
        .stExpander {
            background: rgba(15, 23, 42, 0.4) !important;
            border: 1px solid rgba(255, 255, 255, 0.05) !important;
            border-radius: 12px !important;
        }
        
        .stExpander details summary {
            font-weight: 600 !important;
            color: #e2e8f0 !important;
        }
        
        .stButton button {
            background: linear-gradient(135deg, #4f46e5, #0891b2) !important;
            color: #ffffff !important;
            border: none !important;
            padding: 10px 24px !important;
            border-radius: 10px !important;
            font-weight: 700 !important;
            box-shadow: 0 4px 15px rgba(79, 70, 229, 0.3) !important;
            transition: all 0.3s ease !important;
        }
        
        .stButton button:hover {
            transform: translateY(-2px) !important;
            box-shadow: 0 6px 20px rgba(6, 182, 212, 0.4) !important;
        }
        
        .verdict-box {
            display: flex;
            align-items: center;
            gap: 16px;
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 24px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
            animation: fadeIn 0.4s ease-out;
        }
        
        .verdict-malicious {
            background: rgba(239, 68, 68, 0.08) !important;
            border: 1px solid rgba(239, 68, 68, 0.3) !important;
            color: #f87171 !important;
            box-shadow: 0 4px 20px rgba(239, 68, 68, 0.1) !important;
        }
        
        .verdict-suspicious {
            background: rgba(245, 158, 11, 0.08) !important;
            border: 1px solid rgba(245, 158, 11, 0.3) !important;
            color: #fbbf24 !important;
            box-shadow: 0 4px 20px rgba(245, 158, 11, 0.1) !important;
        }
        
        .verdict-clean {
            background: rgba(16, 185, 129, 0.08) !important;
            border: 1px solid rgba(16, 185, 129, 0.3) !important;
            color: #34d399 !important;
            box-shadow: 0 4px 20px rgba(16, 185, 129, 0.1) !important;
        }

        .pipeline-container {
            margin-top: 20px;
        }
        
        .pipeline-title {
            font-size: 16px !important;
            font-weight: 700 !important;
            color: #f1f5f9 !important;
            margin-bottom: 12px !important;
        }
        
        .pipeline-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 10px 14px;
            background: rgba(15, 23, 42, 0.4);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            margin-bottom: 8px;
        }
        
        .pipeline-icon {
            font-size: 16px;
        }
        
        .pipeline-text {
            display: flex;
            flex-direction: column;
        }
        
        .pipeline-text strong {
            font-size: 12px;
            color: #cbd5e1;
        }
        
        .pipeline-text span {
            font-size: 10px;
            color: #64748b;
        }

        .info-card {
            background: rgba(15, 23, 42, 0.4);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 12px;
            padding: 18px;
            margin-bottom: 16px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        
        .info-card-header {
            font-size: 16px;
            font-weight: 700;
            color: #ffffff;
            margin-bottom: 14px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            padding-bottom: 8px;
        }
        
        .info-card-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.02);
        }
        
        .info-card-row:last-child {
            border-bottom: none;
        }
        
        .info-card-label {
            font-size: 13px;
            color: #94a3b8;
            font-weight: 500;
        }
        
        .info-card-value {
            font-size: 13px;
            color: #cbd5e1;
            font-weight: 600;
        }
        
        .text-monospace {
            font-family: monospace !important;
            font-size: 12px !important;
            color: #818cf8 !important;
        }
        
        .class-badge {
            background: rgba(99, 102, 241, 0.1);
            color: #818cf8;
            padding: 4px 8px;
            border-radius: 6px;
            border: 1px solid rgba(99, 102, 241, 0.2);
        }
        
        .conf-badge {
            background: rgba(16, 185, 129, 0.1);
            color: #34d399;
            padding: 4px 8px;
            border-radius: 6px;
            border: 1px solid rgba(16, 185, 129, 0.2);
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
    plotly_template = "plotly_dark"
    call_graph_color = "#1e293b"
    call_graph_text_color = "#94a3b8"
else:
    # Inject Light theme CSS
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap');
        
        @keyframes fadeIn {
            0% { opacity: 0; transform: translateY(8px); }
            100% { opacity: 1; transform: translateY(0); }
        }
        
        html, body, [class*="css"], .stApp, section[data-testid="stSidebar"] {
            font-family: 'Plus Jakarta Sans', sans-serif !important;
        }
        
        .stApp {
            background: radial-gradient(circle at 50% 50%, #ffffff 0%, #f1f5f9 100%) !important;
            color: #1e293b !important;
            animation: fadeIn 0.4s ease-out;
        }
        
        header[data-testid="stHeader"] {
            background-color: rgba(0,0,0,0) !important;
        }
        
        section[data-testid="stSidebar"] {
            background-color: #ffffff !important;
            border-right: 1px solid #e2e8f0 !important;
        }
        
        section[data-testid="stSidebar"] .stMarkdown, section[data-testid="stSidebar"] h3, section[data-testid="stSidebar"] label, section[data-testid="stSidebar"] span {
            color: #1e293b !important;
        }
        
        [data-testid="stFileUploader"] {
            background: #ffffff !important;
            border: 1px solid #e2e8f0 !important;
            border-radius: 12px !important;
            padding: 16px !important;
        }
        
        [data-testid="stFileUploaderDropzone"] {
            border: 2px dashed rgba(79, 70, 229, 0.3) !important;
            border-radius: 12px !important;
            background-color: #f8fafc !important;
            transition: all 0.3s ease;
        }
        
        [data-testid="stFileUploaderDropzone"]:hover {
            border-color: #0891b2 !important;
            box-shadow: 0 0 15px rgba(8, 145, 178, 0.08) !important;
        }
        
        [data-testid="stFileUploaderDropzone"] * {
            color: #475569 !important;
        }
        
        [data-testid="stFileUploaderDropzone"] button {
            background-color: #4f46e5 !important;
            color: #ffffff !important;
            border: none !important;
            padding: 8px 16px !important;
            border-radius: 8px !important;
            font-weight: 600 !important;
        }
        
        [data-testid="stFileUploaderDropzone"] button:hover {
            background-color: #4338ca !important;
        }
        
        [data-testid="stUploadedFile"], [data-testid="stUploadedFile"] > div {
            background-color: #f8fafc !important;
            border: 1px solid #cbd5e1 !important;
            color: #1e293b !important;
        }
        
        [data-testid="stUploadedFile"] span, [data-testid="stUploadedFile"] p, [data-testid="stUploadedFile"] small, [data-testid="stUploadedFile"] div {
            color: #1e293b !important;
        }
        
        [data-testid="stUploadedFile"] svg {
            fill: #4f46e5 !important;
        }
        
        div[data-baseweb="popover"] * {
            background-color: #ffffff !important;
            color: #1e293b !important;
        }
        
        .main-header {
            display: flex;
            align-items: center;
            gap: 20px;
            padding: 24px 32px;
            background: #ffffff;
            border-radius: 16px;
            border: 1px solid rgba(148, 163, 184, 0.15);
            margin-bottom: 30px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.02);
        }
        
        .header-logo {
            font-size: 40px;
        }
        
        .gradient-title {
            font-size: 36px;
            font-weight: 800;
            margin: 0;
            letter-spacing: -0.5px;
            background: linear-gradient(135deg, #4f46e5, #0891b2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .subtitle {
            font-size: 14px;
            color: #64748b;
            margin: 6px 0 0 0;
            font-weight: 500;
        }
        
        .custom-metrics-grid {
            display: flex;
            flex-direction: column;
            gap: 16px;
        }
        
        .metric-card {
            display: flex;
            align-items: center;
            gap: 16px;
            padding: 16px 20px;
            background: #ffffff;
            border: 1px solid rgba(148, 163, 184, 0.15);
            border-radius: 12px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.02);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        .metric-card:hover {
            transform: translateY(-3px) scale(1.02);
            border-color: rgba(79, 70, 229, 0.3);
            box-shadow: 0 8px 25px rgba(79, 70, 229, 0.08);
        }
        
        .metric-icon {
            font-size: 32px;
            display: flex;
            align-items: center;
            justify-content: center;
            width: 54px;
            height: 54px;
            background: rgba(79, 70, 229, 0.05);
            border-radius: 10px;
            border: 1px solid rgba(79, 70, 229, 0.1);
        }
        
        .metric-content {
            display: flex;
            flex-direction: column;
            flex-grow: 1;
        }
        
        .metric-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            color: #64748b;
            font-weight: 600;
        }
        
        .metric-value {
            font-size: 26px;
            font-weight: 800;
            color: #0f172a;
            line-height: 1.2;
            margin: 4px 0;
        }
        
        .metric-max {
            font-size: 14px;
            color: #94a3b8;
            font-weight: 500;
        }
        
        .metric-progress-bar {
            width: 100%;
            height: 6px;
            background: rgba(0, 0, 0, 0.05);
            border-radius: 4px;
            overflow: hidden;
            margin-top: 6px;
        }
        
        .progress-fill {
            height: 100%;
            border-radius: 4px;
        }
        
        .metric-desc {
            font-size: 11px;
            color: #64748b;
            margin-top: 2px;
        }
        
        .stCodeBlock, .stCodeBlock pre, .stCodeBlock code {
            background-color: #f8fafc !important;
            color: #334155 !important;
            border: 1px solid #e2e8f0 !important;
            border-radius: 8px !important;
        }
        
        .stTabs [data-baseweb="tab-list"] {
            border-bottom: none !important;
            padding: 4px;
            background: rgba(241, 245, 249, 0.8);
            border-radius: 12px;
            border: 1px solid rgba(148, 163, 184, 0.2);
            gap: 8px;
        }
        
        .stTabs [data-baseweb="tab"] {
            padding: 10px 20px !important;
            font-weight: 700 !important;
            color: #475569 !important;
            background: transparent !important;
            border: none !important;
            border-radius: 8px !important;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
        }
        
        .stTabs [aria-selected="true"] {
            background: #ffffff !important;
            color: #4f46e5 !important;
            border: 1px solid rgba(79, 70, 229, 0.15) !important;
            box-shadow: 0 4px 12px rgba(79, 70, 229, 0.08) !important;
        }
        
        .stTabs [data-baseweb="tab"]:hover {
            color: #1e293b !important;
        }
        
        .stExpander {
            background: #ffffff !important;
            border: 1px solid rgba(148, 163, 184, 0.2) !important;
            border-radius: 12px !important;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.02) !important;
        }
        
        .stExpander details summary {
            font-weight: 600 !important;
            color: #1e293b !important;
        }
        
        .stButton button {
            background: linear-gradient(135deg, #4f46e5, #2563eb) !important;
            color: #ffffff !important;
            border: none !important;
            padding: 10px 24px !important;
            border-radius: 10px !important;
            font-weight: 700 !important;
            box-shadow: 0 4px 12px rgba(79, 70, 229, 0.2) !important;
            transition: all 0.3s ease !important;
        }
        
        .stButton button:hover {
            transform: translateY(-2px) !important;
            box-shadow: 0 6px 18px rgba(37, 99, 235, 0.3) !important;
        }
        
        .verdict-box {
            display: flex;
            align-items: center;
            gap: 16px;
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 24px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.02);
            animation: fadeIn 0.4s ease-out;
        }
        
        .verdict-malicious {
            background: #ffebe9 !important;
            border: 1px solid #ff8182 !important;
            color: #cf222e !important;
        }
        
        .verdict-suspicious {
            background: #fff8c5 !important;
            border: 1px solid #d0962b !important;
            color: #9a6700 !important;
        }
        
        .verdict-clean {
            background: #dafbe1 !important;
            border: 1px solid #4ac26b !important;
            color: #1a7f37 !important;
        }

        .pipeline-container {
            margin-top: 20px;
        }
        
        .pipeline-title {
            font-size: 16px !important;
            font-weight: 700 !important;
            color: #1e293b !important;
            margin-bottom: 12px !important;
        }
        
        .pipeline-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 10px 14px;
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            margin-bottom: 8px;
        }
        
        .pipeline-icon {
            font-size: 16px;
        }
        
        .pipeline-text {
            display: flex;
            flex-direction: column;
        }
        
        .pipeline-text strong {
            font-size: 12px;
            color: #1e293b;
        }
        
        .pipeline-text span {
            font-size: 10px;
            color: #64748b;
        }

        .info-card {
            background: #ffffff;
            border: 1px solid rgba(148, 163, 184, 0.15);
            border-radius: 12px;
            padding: 18px;
            margin-bottom: 16px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.02);
        }
        
        .info-card-header {
            font-size: 16px;
            font-weight: 700;
            color: #1e293b;
            margin-bottom: 14px;
            border-bottom: 1px solid rgba(148, 163, 184, 0.1);
            padding-bottom: 8px;
        }
        
        .info-card-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 0;
            border-bottom: 1px solid rgba(148, 163, 184, 0.05);
        }
        
        .info-card-row:last-child {
            border-bottom: none;
        }
        
        .info-card-label {
            font-size: 13px;
            color: #64748b;
            font-weight: 500;
        }
        
        .info-card-value {
            font-size: 13px;
            color: #1e293b;
            font-weight: 600;
        }
        
        .text-monospace {
            font-family: monospace !important;
            font-size: 12px !important;
            color: #4f46e5 !important;
        }
        
        .class-badge {
            background: rgba(79, 70, 229, 0.05);
            color: #4f46e5;
            padding: 4px 8px;
            border-radius: 6px;
            border: 1px solid rgba(79, 70, 229, 0.1);
        }
        
        .conf-badge {
            background: rgba(16, 185, 129, 0.05);
            color: #059669;
            padding: 4px 8px;
            border-radius: 6px;
            border: 1px solid rgba(16, 185, 129, 0.1);
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
    plotly_template = "plotly_white"
    call_graph_color = "#e2e8f0"
    call_graph_text_color = "#475569"

st.markdown(
    """
    <div class="main-header">
        <div class="header-logo">🛡️</div>
        <div class="header-text">
            <h1 class="gradient-title">AegisStatic</h1>
            <p class="subtitle">Next-Generation Static Malware Triage & Payload De-Obfuscation Platform</p>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
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
        """
        <div class="pipeline-container">
            <h3 class="pipeline-title">Operational Pipeline</h3>
            <div class="pipeline-item">
                <div class="pipeline-icon">🔍</div>
                <div class="pipeline-text">
                    <strong>1. Header Parsing</strong>
                    <span>Mitigations & Imports</span>
                </div>
            </div>
            <div class="pipeline-item">
                <div class="pipeline-icon">📊</div>
                <div class="pipeline-text">
                    <strong>2. Entropy Map</strong>
                    <span>High-entropy target search</span>
                </div>
            </div>
            <div class="pipeline-item">
                <div class="pipeline-icon">🔓</div>
                <div class="pipeline-text">
                    <strong>3. De-Obfuscation</strong>
                    <span>XOR & Rot13 payloads</span>
                </div>
            </div>
            <div class="pipeline-item">
                <div class="pipeline-icon">🛡️</div>
                <div class="pipeline-text">
                    <strong>4. Threat Mapping</strong>
                    <span>MITRE ATT&CK Matrix</span>
                </div>
            </div>
            <div class="pipeline-item">
                <div class="pipeline-icon">✍️</div>
                <div class="pipeline-text">
                    <strong>5. YARA Gen</strong>
                    <span>Indicator rule builder</span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
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
                metric_html = f"""
                <div class="custom-metrics-grid">
                    <div class="metric-card risk-card">
                        <div class="metric-icon">🔥</div>
                        <div class="metric-content">
                            <span class="metric-label">Risk Score Index</span>
                            <span class="metric-value">{risk_score:.1f} <span class="metric-max">/ 100</span></span>
                            <div class="metric-progress-bar">
                                <div class="progress-fill" style="width: {risk_score}%; background: linear-gradient(90deg, #f87171, #ef4444);"></div>
                            </div>
                        </div>
                    </div>
                    <div class="metric-card sections-card">
                        <div class="metric-icon">🗂️</div>
                        <div class="metric-content">
                            <span class="metric-label">Suspicious Sections</span>
                            <span class="metric-value">{len(pe_data.get("suspicious_sections", []))}</span>
                            <span class="metric-desc">High entropy or invalid characteristics</span>
                        </div>
                    </div>
                    <div class="metric-card iocs-card">
                        <div class="metric-icon">🚨</div>
                        <div class="metric-content">
                            <span class="metric-label">Threat Indicators</span>
                            <span class="metric-value">{len(iocs)}</span>
                            <span class="metric-desc">Extracted signatures & behaviors</span>
                        </div>
                    </div>
                </div>
                """
                st.markdown(metric_html, unsafe_allow_html=True)
            with col_gauge:
                fig_gauge = go.Figure(go.Indicator(
                    mode = "gauge+number",
                    value = risk_score,
                    domain = {'x': [0, 1], 'y': [0, 1]},
                    title = {'text': "Calculated Threat Index", 'font': {'size': 16, 'color': call_graph_text_color}},
                    gauge = {
                        'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': call_graph_text_color, 'tickfont': {'color': call_graph_text_color}},
                        'bar': {'color': "#f85149" if risk_score > 70 else ("#d29922" if risk_score > 40 else "#3fb950")},
                        'bgcolor': "rgba(0,0,0,0)",
                        'borderwidth': 2,
                        'bordercolor': call_graph_text_color,
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
                profile_html = f"""
                <div class="info-card">
                    <div class="info-card-header">📊 Classification Profile</div>
                    <div class="info-card-row">
                        <span class="info-card-label">Triage Class</span>
                        <span class="info-card-value class-badge">{behavior_profile['class']}</span>
                    </div>
                    <div class="info-card-row">
                        <span class="info-card-label">Confidence Rating</span>
                        <span class="info-card-value conf-badge">{behavior_profile['confidence']}</span>
                    </div>
                </div>
                """
                st.markdown(profile_html, unsafe_allow_html=True)
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
            metadata_html = f"""
            <div class="info-card">
                <div class="info-card-header">📁 File Metadata</div>
                <div class="info-card-row">
                    <span class="info-card-label">Filename</span>
                    <span class="info-card-value text-monospace">{analysis['filename']}</span>
                </div>
                <div class="info-card-row">
                    <span class="info-card-label">File Size</span>
                    <span class="info-card-value">{analysis['file_size']:,} bytes</span>
                </div>
                <div class="info-card-row">
                    <span class="info-card-label">MD5 Hash</span>
                    <span class="info-card-value text-monospace">{analysis['file_hash_md5']}</span>
                </div>
                <div class="info-card-row">
                    <span class="info-card-label">SHA-256 Hash</span>
                    <span class="info-card-value text-monospace">{analysis['file_hash_sha256']}</span>
                </div>
            </div>
            """
            st.markdown(metadata_html, unsafe_allow_html=True)

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
                    font={'color': call_graph_text_color},
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
