"""PDF report generator for AegisStatic static triage analysis results."""

from datetime import datetime
from pathlib import Path
import tempfile

from fpdf import FPDF


class ThreatReport(FPDF):
    """Custom PDF report for AegisStatic analysis results."""

    def header(self):
        self.set_font("Helvetica", "B", 14)
        self.cell(
            0, 10,
            "AegisStatic - Static Triage & Threat Reversal Report",
            align="C", new_x="LMARGIN", new_y="NEXT",
        )
        self.set_font("Helvetica", "", 8)
        self.cell(
            0, 5,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            align="C", new_x="LMARGIN", new_y="NEXT",
        )
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")


def _set_severity_color(pdf: FPDF, severity: str) -> None:
    """Set fill color based on severity level."""
    colors = {
        "Critical": (220, 53, 69),
        "High": (255, 152, 0),
        "Medium": (255, 193, 7),
        "Low": (40, 167, 69),
        "Info": (108, 117, 125),
    }
    r, g, b = colors.get(severity, (108, 117, 125))
    pdf.set_fill_color(r, g, b)


def _set_risk_color(pdf: FPDF, score: float) -> None:
    """Set text color based on risk score."""
    if score > 70:
        pdf.set_text_color(220, 53, 69)
    elif score > 40:
        pdf.set_text_color(255, 152, 0)
    else:
        pdf.set_text_color(40, 167, 69)


def _add_section_heading(pdf: FPDF, title: str) -> None:
    """Add a styled section heading."""
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(33, 37, 41)
    pdf.set_fill_color(233, 236, 239)
    pdf.cell(0, 8, title, fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)


def _safe_text(text: str) -> str:
    """Strip characters that fpdf2 cannot encode in latin-1."""
    return text.encode("latin-1", errors="replace").decode("latin-1")


def generate_pdf_report(analysis_data: dict, output_path: str = None) -> str:
    """Generate a comprehensive PDF report from analysis results."""
    if output_path is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = str(Path(tempfile.gettempdir()) / f"aegisstatic_report_{ts}.pdf")

    pdf = ThreatReport()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    col_w = pdf.w - pdf.l_margin - pdf.r_margin

    # ------------------------------------------------------------------
    # 1. Executive Summary
    # ------------------------------------------------------------------
    _add_section_heading(pdf, "1. Executive Summary")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(33, 37, 41)

    filename = analysis_data.get("filename", "N/A")
    md5 = analysis_data.get("file_hash_md5", "N/A")
    sha256 = analysis_data.get("file_hash_sha256", "N/A")
    file_size = analysis_data.get("file_size", 0)
    risk_score = analysis_data.get("risk_score", 0.0)

    # Behavior profile
    behavior = analysis_data.get("behavior_profile", {})
    b_class = behavior.get("class", "Suspicious Binary")
    b_conf = behavior.get("confidence", "Low")

    # MalwareBazaar Info
    bazaar = analysis_data.get("malwarebazaar", {})
    bazaar_status = "NOT FOUND in database"
    if bazaar.get("found"):
        bazaar_status = f"FOUND | Family: {bazaar.get('signature')} | Tags: {', '.join(bazaar.get('tags', []))}"

    meta_rows = [
        ("Filename", _safe_text(filename)),
        ("File Size", f"{file_size:,} bytes"),
        ("MD5", md5),
        ("SHA-256", sha256),
        ("Behavior Profile", f"{b_class} (Confidence: {b_conf})"),
        ("MalwareBazaar Threat Intel", _safe_text(bazaar_status))
    ]
    label_w = 45
    val_w = col_w - label_w
    for label, value in meta_rows:
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(label_w, 5.5, label + ":", new_x="RIGHT", new_y="TOP")
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(val_w, 5.5, _safe_text(value), new_x="LMARGIN", new_y="NEXT")

    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(label_w, 8, "Calculated Risk Score:", new_x="RIGHT", new_y="TOP")
    _set_risk_color(pdf, risk_score)
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(val_w, 8, f"{risk_score:.1f} / 100", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(33, 37, 41)
    pdf.ln(4)

    # ------------------------------------------------------------------
    # 2. Binary Mitigations Status
    # ------------------------------------------------------------------
    _add_section_heading(pdf, "2. Binary Security Mitigations")
    pdf.set_font("Helvetica", "", 9)
    
    mitigations = [
        ("ASLR (Address Space Layout Randomization)", "Yes" if analysis_data.get("aslr") else "No"),
        ("DEP/NX (Data Execution Prevention)", "Yes" if analysis_data.get("dep") else "No"),
        ("Control Flow Guard (CFG)", "Yes" if analysis_data.get("cfg") else "No"),
        ("SafeSEH (Structured Exception Handling Protection)", "Yes" if analysis_data.get("safeseh") else "No"),
        ("Authenticode Digital Signature", "Yes" if analysis_data.get("authenticode") else "No")
    ]

    mit_label_w = 80
    mit_val_w = col_w - mit_label_w
    for label, value in mitigations:
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(mit_label_w, 5.5, label + ":", border=1, new_x="RIGHT", new_y="TOP")
        
        pdf.set_font("Helvetica", "", 9)
        if value == "Yes":
            pdf.set_fill_color(224, 242, 224) # Light green
            pdf.cell(mit_val_w, 5.5, "ENABLED", border=1, fill=True, align="C", new_x="LMARGIN", new_y="NEXT")
        else:
            pdf.set_fill_color(253, 235, 235) # Light red
            pdf.cell(mit_val_w, 5.5, "DISABLED", border=1, fill=True, align="C", new_x="LMARGIN", new_y="NEXT")

    pdf.ln(4)

    # ------------------------------------------------------------------
    # 3. Section Analysis
    # ------------------------------------------------------------------
    _add_section_heading(pdf, "3. PE Section Analysis")

    sections = analysis_data.get("sections", [])
    if not sections:
        pdf.set_font("Helvetica", "I", 10)
        pdf.cell(0, 6, "No sections found.", new_x="LMARGIN", new_y="NEXT")
    else:
        headers = ["Section", "Virtual Size", "Raw Size", "Entropy", "Suspicious"]
        widths = [col_w * 0.22, col_w * 0.2, col_w * 0.2, col_w * 0.18, col_w * 0.2]

        pdf.set_font("Helvetica", "B", 9)
        pdf.set_fill_color(52, 58, 64)
        pdf.set_text_color(255, 255, 255)
        for i, h in enumerate(headers):
            pdf.cell(widths[i], 7, h, border=1, fill=True, align="C",
                     new_x="RIGHT", new_y="TOP")
        pdf.ln()

        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(33, 37, 41)

        for sec in sections:
            name = sec.get("name", sec.name if hasattr(sec, "name") else "?")
            vsize = sec.get("virtual_size", getattr(sec, "virtual_size", 0))
            rsize = sec.get("raw_size", getattr(sec, "raw_size", 0))
            entropy = sec.get("entropy", getattr(sec, "entropy", 0.0))
            suspicious = sec.get("is_suspicious", getattr(sec, "is_suspicious", False))

            if suspicious:
                pdf.set_fill_color(255, 235, 238)
            else:
                pdf.set_fill_color(255, 255, 255)

            row_data = [
                _safe_text(str(name)),
                f"{vsize:,}",
                f"{rsize:,}",
                f"{entropy:.4f}",
                "YES" if suspicious else "No",
            ]
            for i, val in enumerate(row_data):
                pdf.cell(widths[i], 6, val, border=1, fill=True, align="C",
                         new_x="RIGHT", new_y="TOP")
            pdf.ln()

    pdf.ln(4)

    # ------------------------------------------------------------------
    # 4. Decryption Findings
    # ------------------------------------------------------------------
    _add_section_heading(pdf, "4. Decryption & De-obfuscation Findings")

    decryption_results = analysis_data.get("decryption_results", [])
    if not decryption_results:
        pdf.set_font("Helvetica", "I", 10)
        pdf.cell(0, 6, "No decryption results found.", new_x="LMARGIN", new_y="NEXT")
    else:
        sorted_results = sorted(
            decryption_results,
            key=lambda r: r.get("confidence_score", 0),
            reverse=True,
        )

        for idx, res in enumerate(sorted_results[:15], start=1):
            xor_hex = res.get("xor_key_hex", f"0x{res.get('xor_key', 0):02X}")
            confidence = res.get("confidence_score", 0.0)
            keyword_hits = res.get("keyword_hits", [])
            source = res.get("source_section", "?")
            decrypted = res.get("decrypted_text", "")

            if pdf.get_y() > pdf.h - 50:
                pdf.add_page()

            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(
                0, 6,
                f"Result #{idx}  |  Key/Type: {xor_hex}  |  Section: {_safe_text(source)}  "
                f"|  Confidence: {confidence * 100:.1f}%",
                new_x="LMARGIN", new_y="NEXT",
            )

            if keyword_hits:
                pdf.set_font("Helvetica", "", 9)
                hits_str = ", ".join(str(k) for k in keyword_hits[:10])
                pdf.cell(
                    0, 5,
                    f"  Keyword Hits: {_safe_text(hits_str)}",
                    new_x="LMARGIN", new_y="NEXT",
                )

            preview = _safe_text(decrypted[:200])
            if len(decrypted) > 200:
                preview += "..."
            pdf.set_font("Courier", "", 8)
            pdf.set_fill_color(248, 249, 250)
            pdf.multi_cell(col_w, 4, preview, fill=True,
                           new_x="LMARGIN", new_y="NEXT")
            pdf.ln(3)

    pdf.ln(2)

    # ------------------------------------------------------------------
    # 5. IOC Summary
    # ------------------------------------------------------------------
    _add_section_heading(pdf, "5. Indicators of Compromise (IOCs)")

    iocs = analysis_data.get("iocs", [])
    if not iocs:
        pdf.set_font("Helvetica", "I", 10)
        pdf.cell(0, 6, "No IOCs extracted.", new_x="LMARGIN", new_y="NEXT")
    else:
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        sorted_iocs = sorted(
            iocs,
            key=lambda x: severity_order.get(x.get("severity", "Info"), 5),
        )

        ioc_headers = ["Type", "Value", "Severity", "MITRE ID", "Technique"]
        ioc_widths = [col_w * 0.15, col_w * 0.32, col_w * 0.12, col_w * 0.13, col_w * 0.28]

        pdf.set_font("Helvetica", "B", 8)
        pdf.set_fill_color(52, 58, 64)
        pdf.set_text_color(255, 255, 255)
        for i, h in enumerate(ioc_headers):
            pdf.cell(ioc_widths[i], 7, h, border=1, fill=True, align="C",
                     new_x="RIGHT", new_y="TOP")
        pdf.ln()

        pdf.set_text_color(33, 37, 41)
        pdf.set_font("Helvetica", "", 7)

        for ioc in sorted_iocs[:50]:
            if pdf.get_y() > pdf.h - 25:
                pdf.add_page()
                pdf.set_font("Helvetica", "B", 8)
                pdf.set_fill_color(52, 58, 64)
                pdf.set_text_color(255, 255, 255)
                for i, h in enumerate(ioc_headers):
                    pdf.cell(ioc_widths[i], 7, h, border=1, fill=True, align="C",
                             new_x="RIGHT", new_y="TOP")
                pdf.ln()
                pdf.set_text_color(33, 37, 41)
                pdf.set_font("Helvetica", "", 7)

            severity = ioc.get("severity", "Info")
            _set_severity_color(pdf, severity)
            
            ioc_type = _safe_text(str(ioc.get("ioc_type", "")))
            value = _safe_text(str(ioc.get("value", ""))[:65])
            mitre_id = _safe_text(str(ioc.get("mitre_technique_id", "")))
            technique = _safe_text(str(ioc.get("mitre_technique_name", ""))[:45])

            pdf.set_fill_color(255, 255, 255)
            pdf.cell(ioc_widths[0], 5.5, ioc_type, border=1, align="C",
                     new_x="RIGHT", new_y="TOP")
            pdf.cell(ioc_widths[1], 5.5, value, border=1,
                     new_x="RIGHT", new_y="TOP")

            _set_severity_color(pdf, severity)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(ioc_widths[2], 5.5, severity, border=1, fill=True, align="C",
                     new_x="RIGHT", new_y="TOP")
            pdf.set_text_color(33, 37, 41)

            pdf.set_fill_color(255, 255, 255)
            pdf.cell(ioc_widths[3], 5.5, mitre_id, border=1, align="C",
                     new_x="RIGHT", new_y="TOP")
            pdf.cell(ioc_widths[4], 5.5, technique, border=1,
                     new_x="RIGHT", new_y="TOP")
            pdf.ln()

    pdf.ln(4)

    # ------------------------------------------------------------------
    # 6. MITRE ATT&CK Coverage
    # ------------------------------------------------------------------
    _add_section_heading(pdf, "6. MITRE ATT&CK Coverage")

    mitre_summary = analysis_data.get("mitre_summary", {})
    if not mitre_summary:
        pdf.set_font("Helvetica", "I", 10)
        pdf.cell(0, 6, "No MITRE ATT&CK mappings found.", new_x="LMARGIN", new_y="NEXT")
    else:
        mitre_headers = ["Tactic", "Techniques", "Details"]
        mitre_widths = [col_w * 0.28, col_w * 0.12, col_w * 0.60]

        pdf.set_font("Helvetica", "B", 9)
        pdf.set_fill_color(52, 58, 64)
        pdf.set_text_color(255, 255, 255)
        for i, h in enumerate(mitre_headers):
            pdf.cell(mitre_widths[i], 7, h, border=1, fill=True, align="C",
                     new_x="RIGHT", new_y="TOP")
        pdf.ln()

        pdf.set_text_color(33, 37, 41)
        pdf.set_font("Helvetica", "", 9)

        for tactic, details in mitre_summary.items():
            if pdf.get_y() > pdf.h - 25:
                pdf.add_page()

            if isinstance(details, dict):
                tech_count = str(details.get("technique_count", len(details)))
                tech_list = details.get("techniques", [])
                if isinstance(tech_list, list):
                    detail_str = ", ".join(
                        t.get("name", str(t)) if isinstance(t, dict) else str(t)
                        for t in tech_list[:5]
                    )
                else:
                    detail_str = str(tech_list)
            elif isinstance(details, list):
                tech_count = str(len(details))
                detail_str = ", ".join(str(t) for t in details[:5])
            else:
                tech_count = "1"
                detail_str = str(details)

            pdf.set_fill_color(248, 249, 250)
            pdf.cell(mitre_widths[0], 6, _safe_text(str(tactic)), border=1,
                     fill=True, new_x="RIGHT", new_y="TOP")
            pdf.cell(mitre_widths[1], 6, tech_count, border=1,
                     fill=True, align="C", new_x="RIGHT", new_y="TOP")
            pdf.cell(mitre_widths[2], 6, _safe_text(detail_str[:80]), border=1,
                     fill=True, new_x="RIGHT", new_y="TOP")
            pdf.ln()

    pdf.output(output_path)
    return output_path
