# -*- coding: utf-8 -*-
"""
NPE Learner PDF Analyzer — Flask REST API
Analyzes uploaded PDF files for structural anomalies and potential threats.
"""
import os
import sys
import json
import hashlib
import traceback
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS

# Add parser to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parser.main import PDF, FeatureType

app = Flask(__name__)
CORS(app)

# Risk weights for each feature category
RISK_WEIGHTS = {
    'javascript': 0.30,
    'suspicious_names': 0.25,
    'embedded_files': 0.20,
    'format_errors': 0.15,
    'obfuscation': 0.10,
}


def calculate_risk_score(features, pdf_obj):
    """Calculate a 0-100 risk score based on extracted features."""
    scores = {}

    # JavaScript risk (0-100)
    js_score = 0
    js_count = len(pdf_obj.javascripts)
    js_size_ratio = features.get('js_ratio_in_size', 0)
    js_max_line = features.get('js_max_line_length', 0)
    if js_count > 0:
        js_score += min(40, js_count * 20)
    if js_size_ratio > 0.1:
        js_score += 30
    if js_max_line > 500:
        js_score += 30
    scores['javascript'] = min(100, js_score)

    # Suspicious names risk (0-100)
    suspicious = features.get('num_suspicious_name', {})
    sus_total = sum(suspicious.values()) if isinstance(suspicious, dict) else 0
    high_risk_names = ['num_name_JS', 'num_name_JavaScript', 'num_name_Launch',
                       'num_name_OpenAction', 'num_name_AA', 'num_name_RichMedia']
    high_risk_count = sum(1 for k in high_risk_names
                          if k in suspicious or k.replace('num_name_', 'num_name_') in suspicious)
    scores['suspicious_names'] = min(100, sus_total * 10 + high_risk_count * 25)

    # Embedded files risk (0-100)
    num_file = features.get('num_file', {})
    embed_total = sum(num_file.values()) if isinstance(num_file, dict) else 0
    pe_count = num_file.get('num_file_pe', 0)
    scores['embedded_files'] = min(100, embed_total * 15 + pe_count * 50)

    # Format errors risk (0-100)
    errors = features.get('format_error', {})
    err_total = sum(errors.values()) if isinstance(errors, dict) else 0
    scores['format_errors'] = min(100, err_total * 8)

    # Obfuscation risk (0-100)
    hex_ratio = features.get('ratio_hex_in_name', 0)
    hex_filter = features.get('num_hex_in_filter_name', 0)
    multi_filter = features.get('num_multi_filter', {})
    multi_total = sum(multi_filter.values()) if isinstance(multi_filter, dict) else 0
    obf_score = 0
    if hex_ratio > 0.3:
        obf_score += 40
    obf_score += min(30, hex_filter * 15)
    obf_score += min(30, multi_total * 10)
    scores['obfuscation'] = min(100, obf_score)

    # Weighted total
    total = sum(scores[k] * RISK_WEIGHTS[k] for k in RISK_WEIGHTS)
    return round(total, 1), scores


def generate_report(features, pdf_obj, risk_score, category_scores):
    """Generate a detailed English text report."""
    sections = []

    # Overall verdict
    if risk_score >= 70:
        verdict = "HIGH RISK"
        verdict_desc = ("This PDF exhibits multiple characteristics commonly associated with "
                        "malicious documents. It is strongly recommended to avoid opening this "
                        "file in a standard PDF viewer and to submit it for further malware analysis.")
    elif risk_score >= 40:
        verdict = "MEDIUM RISK"
        verdict_desc = ("This PDF contains some suspicious elements that warrant caution. "
                        "While not definitively malicious, certain structural features deviate "
                        "from typical benign documents. Exercise caution when opening.")
    elif risk_score >= 15:
        verdict = "LOW RISK"
        verdict_desc = ("This PDF shows minor anomalies that are occasionally found in both "
                        "benign and crafted documents. Overall structure appears mostly normal, "
                        "but review the detailed findings below.")
    else:
        verdict = "CLEAN"
        verdict_desc = ("This PDF appears to be a standard, well-formed document with no "
                        "significant anomalies detected. The structural analysis shows patterns "
                        "consistent with benign PDF files.")

    sections.append({
        'title': 'Overall Assessment',
        'verdict': verdict,
        'content': verdict_desc
    })

    # JavaScript Analysis
    js_content = ""
    js_count = len(pdf_obj.javascripts)
    if js_count > 0:
        js_apis = features.get('js_num_api', {})
        js_content = (f"Detected {js_count} JavaScript block(s) embedded within the document. "
                      f"JavaScript in PDFs is frequently exploited to trigger buffer overflows, "
                      f"heap sprays, or other memory corruption vulnerabilities in PDF readers. ")
        if features.get('js_max_line_length', 0) > 500:
            js_content += (f"The maximum line length of {features['js_max_line_length']} characters "
                           f"is unusually long, which is a common indicator of obfuscated code. ")
        if js_apis:
            api_list = ', '.join(k.replace('js_num_api_', '') for k in list(js_apis.keys())[:10])
            js_content += f"Detected JavaScript API calls: {api_list}. "
        js_content += (f"JavaScript accounts for {features.get('js_ratio_in_size', 0)*100:.1f}% "
                       f"of the total file size.")
    else:
        js_content = ("No JavaScript code was detected in this document. This is a positive "
                      "indicator, as embedded JavaScript is one of the primary attack vectors "
                      "in malicious PDFs.")
    sections.append({'title': 'JavaScript Analysis', 'content': js_content})

    # Stream Filter Analysis
    filters = features.get('num_filter', {})
    filter_content = "Stream filters control how data is encoded within the PDF. "
    if filters:
        filter_list = ', '.join(f"{k.replace('num_filter_', '')}: {v}" for k, v in filters.items() if v > 0)
        filter_content += f"Detected filters: {filter_list}. "
        multi = features.get('num_multi_filter', {})
        if multi:
            multi_list = ', '.join(f"{k}: {v}" for k, v in multi.items() if v > 0)
            filter_content += (f"Multi-layer filter chains detected: {multi_list}. "
                               f"Stacked filters can be used to obfuscate malicious payloads "
                               f"by encoding them through multiple compression/encoding layers.")
    else:
        filter_content += "No unusual filter configurations detected."
    sections.append({'title': 'Stream Filter Analysis', 'content': filter_content})

    # Suspicious Names
    suspicious = features.get('num_suspicious_name', {})
    names_content = ("PDF name objects (like /JS, /OpenAction, /Launch) can indicate "
                     "automatic actions or embedded functionality. ")
    if suspicious:
        name_list = ', '.join(f"{k.replace('num_name_', '/')}: {v}" for k, v in suspicious.items() if v > 0)
        names_content += f"Detected suspicious names: {name_list}. "
        if any('JS' in k or 'JavaScript' in k for k in suspicious):
            names_content += "The presence of /JS or /JavaScript names indicates script execution triggers. "
        if any('OpenAction' in k or 'AA' in k for k in suspicious):
            names_content += ("The /OpenAction or /AA (Additional Actions) names suggest automatic "
                              "code execution when the document is opened. ")
        if any('Launch' in k for k in suspicious):
            names_content += "The /Launch action can be used to execute arbitrary system commands. "
    else:
        names_content += "No suspicious PDF name objects were found in this document."
    sections.append({'title': 'Suspicious Name Objects', 'content': names_content})

    # Embedded Files
    embed_content = "Embedded files within PDFs can carry secondary payloads. "
    total_embeds = sum(len(v) for v in pdf_obj.embedded_files.values())
    if total_embeds > 0:
        for ftype, flist in pdf_obj.embedded_files.items():
            if flist:
                embed_content += f"Found {len(flist)} embedded {ftype.upper()} file(s). "
        if pdf_obj.embedded_files.get('pe'):
            embed_content += ("WARNING: Embedded PE (Windows executable) files detected. "
                              "This is a strong indicator of a dropper-style attack. ")
    else:
        embed_content += "No embedded files (PE, PDF, SWF) were detected."
    sections.append({'title': 'Embedded File Detection', 'content': embed_content})

    # Structure Integrity
    err_content = f"Detected {len(pdf_obj.errors)} structural anomaly/anomalies. "
    if pdf_obj.errors:
        for err in pdf_obj.errors[:5]:
            if hasattr(err, 'err_msg'):
                err_content += f"• {err.err_msg} "
        err_content += ("Structural errors can indicate file manipulation, attempts to exploit "
                        "parser vulnerabilities, or simple corruption. Malicious PDFs often "
                        "intentionally introduce format errors to confuse security tools.")
    else:
        err_content += ("The document structure is well-formed with no parsing errors detected. "
                        "This is consistent with standard PDF generation tools.")
    sections.append({'title': 'Structure Integrity', 'content': err_content})

    # Tail Data
    if pdf_obj.tail and len(pdf_obj.tail) > 10:
        tail_content = (f"Detected {len(pdf_obj.tail)} bytes of appended data after the %%EOF marker. "
                        f"Entropy: {features.get('appended_tail_entropy', 0):.2f}. "
                        f"Appended data after the PDF end-of-file marker can contain hidden payloads, "
                        f"shellcode, or encrypted content used by exploit kits.")
        sections.append({'title': 'Appended Tail Data', 'content': tail_content})

    return sections


def serialize_features(features):
    """Convert bytes keys/values to strings for JSON serialization."""
    if isinstance(features, dict):
        return {
            (k.decode() if isinstance(k, bytes) else str(k)):
            serialize_features(v)
            for k, v in features.items()
        }
    elif isinstance(features, list):
        return [serialize_features(x) for x in features]
    elif isinstance(features, bytes):
        return k.decode(errors='replace')
    else:
        return features


@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'service': 'pdf-analyzer'})


@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if not file.filename:
        return jsonify({'error': 'No filename'}), 400

    try:
        bytes_pdf = file.read()
        file_size = len(bytes_pdf)
        sha256 = hashlib.sha256(bytes_pdf).hexdigest()
        md5 = hashlib.md5(bytes_pdf).hexdigest()

        # Parse PDF
        pdf = PDF()
        pdf.parse(bytes_pdf=bytes_pdf)

        # Extract features
        feature_types = FeatureType.all()
        features = pdf.make_features(feature_types)

        # Calculate risk score
        risk_score, category_scores = calculate_risk_score(features, pdf)

        # Generate detailed report
        report_sections = generate_report(features, pdf, risk_score, category_scores)

        # Build filter distribution for chart
        filter_dist = {}
        for k, v in features.get('num_filter', {}).items():
            name = k.replace('num_filter_', '')
            if v > 0:
                filter_dist[name] = v

        # Suspicious name distribution
        suspicious_dist = {}
        for k, v in features.get('num_suspicious_name', {}).items():
            name = k.replace('num_name_', '/')
            if v > 0:
                suspicious_dist[name] = v

        result = {
            'file_info': {
                'filename': file.filename,
                'size': file_size,
                'sha256': sha256,
                'md5': md5,
                'pdf_version': pdf.ver.decode() if pdf.ver else 'Unknown',
                'analyzed_at': datetime.utcnow().isoformat() + 'Z',
            },
            'risk_score': risk_score,
            'verdict': report_sections[0]['verdict'],
            'category_scores': category_scores,
            'statistics': {
                'total_objects': len(pdf.objs),
                'total_streams': pdf.features.get('num_stream', 0),
                'total_javascripts': len(pdf.javascripts),
                'total_errors': len(pdf.errors),
                'total_embedded_files': sum(len(v) for v in pdf.embedded_files.values()),
                'correct_objects': pdf.features.get('num_correct_obj', 0),
                'corrupted_objects': pdf.features.get('num_corrupted_obj', 0),
            },
            'charts': {
                'filter_distribution': filter_dist,
                'suspicious_names': suspicious_dist,
            },
            'raw_features': {
                'file_size': features.get('file_size', 0),
                'ratio_hex_in_name': round(features.get('ratio_hex_in_name', 0), 4),
                'num_hex_in_filter_name': features.get('num_hex_in_filter_name', 0),
                'num_cmd': features.get('num_cmd', 0),
                'js_max_line_length': features.get('js_max_line_length', 0),
                'js_ratio_in_size': round(features.get('js_ratio_in_size', 0), 4),
                'appended_tail_len': features.get('appended_tail_len', 0),
                'appended_tail_entropy': round(features.get('appended_tail_entropy', 0), 4),
            },
            'report': report_sections,
        }

        return jsonify(result)

    except Exception as e:
        traceback.print_exc()
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
