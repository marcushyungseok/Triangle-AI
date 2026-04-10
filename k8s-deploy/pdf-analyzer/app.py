# -*- coding: utf-8 -*-
"""
NPE Learner Multi-Format Analyzer — Flask REST API
Supports PDF, MS Office, JavaScript, HTML, and LNK files.
"""
import os
import sys
import json
import hashlib
import traceback
import magic
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS

# Add parser to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parser.main import PDF, FeatureType

# Optional: oletools for Office analysis
try:
    from oletools.mraptor import MacroRaptor
    from oletools.oleid import OleID
    OLE_TOOLS_AVAILABLE = True
except ImportError:
    OLE_TOOLS_AVAILABLE = False

app = Flask(__name__)
CORS(app)

# --------------------------------------------------------------------------
# Analysis Dispatcher
# --------------------------------------------------------------------------

def analyze_file(file_bytes, filename):
    """Detect file type and route to appropriate analyzer."""
    mime = magic.from_buffer(file_bytes, mime=True)
    extension = os.path.splitext(filename)[1].lower()

    if mime == 'application/pdf' or extension == '.pdf':
        return analyze_pdf(file_bytes, filename)
    elif mime in ['application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                  'application/msword', 'application/vnd.ms-excel',
                  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'] or \
         extension in ['.doc', '.docx', '.xls', '.xlsx', '.docm', '.xlsm']:
        return analyze_office(file_bytes, filename)
    elif mime in ['text/javascript', 'application/javascript', 'text/x-javascript'] or \
         extension in ['.js', '.vbs', '.ps1']:
        return analyze_script(file_bytes, filename, 'script')
    elif mime == 'text/html' or extension in ['.html', '.htm']:
        return analyze_script(file_bytes, filename, 'html')
    elif extension == '.lnk':
        return analyze_lnk(file_bytes, filename)
    else:
        # Generic binary/text analysis
        return analyze_generic(file_bytes, filename, mime)

# --------------------------------------------------------------------------
# PDF Analyzer (Existing)
# --------------------------------------------------------------------------

def analyze_pdf(bytes_data, filename):
    pdf = PDF()
    pdf.parse(bytes_pdf=bytes_data)
    features = pdf.make_features(FeatureType.all())
    
    # Simple risk scoring logic (reusing existing one)
    score = 0
    reasons = []
    
    js_count = len(pdf.javascripts)
    if js_count > 0:
        score += 30
        reasons.append(f"Detected {js_count} JavaScript block(s)")
    
    if features.get('num_file_pe', 0) > 0:
        score += 50
        reasons.append("Embedded Windows Executable (PE) found")
        
    if len(pdf.errors) > 0:
        score += 10
        reasons.append(f"Detected {len(pdf.errors)} structural errors")

    verdict = "CLEAN"
    if score >= 70: verdict = "HIGH RISK"
    elif score >= 30: verdict = "MEDIUM RISK"

    return {
        'type': 'PDF Document',
        'risk_score': min(100, score),
        'verdict': verdict,
        'details': reasons,
        'stats': {
            'objects': len(pdf.objs),
            'scripts': js_count,
            'embedded': sum(len(v) for v in pdf.embedded_files.values())
        }
    }

# --------------------------------------------------------------------------
# Office Analyzer (New)
# --------------------------------------------------------------------------

def analyze_office(bytes_data, filename):
    if not OLE_TOOLS_AVAILABLE:
        return {'type': 'Office Document', 'error': 'Office analysis tools not available'}

    import tempfile
    
    score = 0
    reasons = []
    is_suspicious = False

    # Create a temporary file because oletools often works better with actual files
    with tempfile.NamedTemporaryFile(suffix=os.path.splitext(filename)[1], delete=False) as tmp:
        tmp.write(bytes_data)
        tmp_path = tmp.name

    try:
        # 1. MacroRaptor check
        mr = MacroRaptor(tmp_path)
        mr.scan()
        if mr.suspicious:
            is_suspicious = True
            score += 60
            reasons.append("Suspicious VBA Macros detected (Auto-exec / dangerous APIs)")
        
        # 2. OleID check
        # For OleID, it sometimes takes a filename or data
        oid = OleID(tmp_path)
        indicators = oid.check()
        for indicator in indicators:
            if indicator.id == 'encrypted' and indicator.value is True:
                score += 20
                reasons.append("Encrypted/Password-protected document")
            if indicator.id == 'vba_macros' and indicator.value is True:
                if not is_suspicious:
                    score += 10
                    reasons.append("Contains VBA Macros (but not immediately flagged as malicious)")
            if indicator.id == 'external_relationships' and hasattr(indicator, 'value') and isinstance(indicator.value, int) and indicator.value > 0:
                score += 15
                reasons.append(f"External relationships found ({indicator.value})")
    except Exception as e:
        reasons.append(f"Analysis warning: {str(e)}")
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    verdict = "CLEAN"
    if score >= 60: verdict = "HIGH RISK"
    elif score >= 20: verdict = "MEDIUM RISK"

    return {
        'type': 'Office Document',
        'risk_score': min(100, score),
        'verdict': verdict,
        'details': reasons,
        'stats': {
            'macro_suspicious': is_suspicious,
            'indicators': len(reasons)
        }
    }

# --------------------------------------------------------------------------
# Script/HTML Analyzer (New)
# --------------------------------------------------------------------------

def analyze_script(bytes_data, filename, mode):
    content = bytes_data.decode(errors='ignore').lower()
    score = 0
    reasons = []

    # Suspicious Keywords
    keywords = {
        'eval(': 25,
        'unescape(': 15,
        'document.write(': 15,
        'string.fromcharcode': 20,
        'xmlhttprequest': 10,
        'powershell': 40,
        'cmd.exe': 40,
        'base64': 10,
        'activexobject': 30
    }

    for kw, val in keywords.items():
        if kw in content:
            score += val
            reasons.append(f"Found suspicious keyword: {kw}")

    if len(content) > 10000 and score > 20:
        score += 10 # Obfuscation hint

    verdict = "CLEAN"
    if score >= 60: verdict = "HIGH RISK"
    elif score >= 25: verdict = "MEDIUM RISK"

    return {
        'type': 'HTML/Script File' if mode == 'html' else 'Source Script',
        'risk_score': min(100, score),
        'verdict': verdict,
        'details': reasons,
        'stats': {
            'length': len(content),
            'tokens_found': len(reasons)
        }
    }

# --------------------------------------------------------------------------
# LNK Analyzer (New)
# --------------------------------------------------------------------------

def analyze_lnk(bytes_data, filename):
    content = bytes_data.decode(errors='ignore').lower()
    score = 20 # Baseline for LNK files as they are often used for attacks
    reasons = ["LNK files are frequently used as launch vehicles"]

    if 'powershell' in content:
        score += 50
        reasons.append("Contains PowerShell execution command")
    if 'cmd.exe' in content or '/c' in content:
        score += 30
        reasons.append("Contains Command Prompt execution")
    if 'http' in content:
        score += 20
        reasons.append("Contains remote URL for download")

    verdict = "HIGH RISK" if score >= 70 else "MEDIUM RISK"

    return {
        'type': 'Windows Shortcut (LNK)',
        'risk_score': min(100, score),
        'verdict': verdict,
        'details': reasons,
        'stats': {}
    }

def analyze_generic(bytes_data, filename, mime):
    return {
        'type': f'Generic File ({mime})',
        'risk_score': 0,
        'verdict': 'UNKNOWN',
        'details': ["No specialized analyzer for this file type."],
        'stats': {}
    }

# --------------------------------------------------------------------------
# Flask Routes
# --------------------------------------------------------------------------

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'service': 'multi-analyzer'})

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if not file.filename:
        return jsonify({'error': 'No filename'}), 400

    try:
        bytes_data = file.read()
        sha256 = hashlib.sha256(bytes_data).hexdigest()
        
        # Dispatch to appropriate analyzer
        analysis = analyze_file(bytes_data, file.filename)
        
        # Meta report wrap
        result = {
            'file_info': {
                'filename': file.filename,
                'size': len(bytes_data),
                'sha256': sha256,
                'mime_type': magic.from_buffer(bytes_data, mime=True),
                'analyzed_at': datetime.utcnow().isoformat() + 'Z',
            },
            'type': analysis['type'],
            'risk_score': analysis['risk_score'],
            'verdict': analysis['verdict'],
            'details': analysis['details'],
            'stats': analysis['stats'],
            'report': [
                {'title': 'Analysis Summary', 'content': f"Detected file as {analysis['type']}. Check the details for findings."},
                {'title': 'Detection Results', 'content': "\n".join(f"• {d}" for d in analysis['details']) if analysis['details'] else "No suspicious elements found."}
            ]
        }

        return jsonify(result)

    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
