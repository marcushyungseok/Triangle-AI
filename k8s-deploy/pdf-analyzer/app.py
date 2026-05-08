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
import requests
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
    if score >= 80: verdict = "HIGH RISK"
    elif score >= 40: verdict = "MEDIUM RISK"

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

    # Suspicious Keywords — require multiple indicators for meaningful score
    keywords = {
    'eval(': 10,
    'unescape(': 5,
    'document.write(': 10,
    'string.fromcharcode': 10,
    'xmlhttprequest': 3,
    'powershell': 35,
    'cmd.exe': 35,
    'base64': 2,
    'activexobject': 25,
    'wscript.shell': 35,
    'fromcharcode': 5,
    }

    found_count = 0
    for kw, val in keywords.items():
        if kw in content:
            score += val
            reasons.append(f"Found suspicious keyword: {kw}")
            found_count += 1

    # Bonus: multiple suspicious keywords compound the risk
    if found_count >= 3:
        score += 15
        reasons.append(f"Multiple suspicious patterns detected ({found_count} keywords)")

    # Obfuscation hint: large file with suspicious keywords
    if len(content) > 10000 and found_count >= 2:
        score += 10

    verdict = "CLEAN"
    if score >= 85: verdict = "HIGH RISK"
    elif score >= 50: verdict = "MEDIUM RISK"

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

def generate_ai_insight(analysis_data):
    """Call local Ollama API to generate a sophisticated security report."""
    ollama_url = os.environ.get('OLLAMA_URL', 'http://host.minikube.internal:11434')
    model = os.environ.get('OLLAMA_MODEL', 'gemma4:e2b')
    
    prompt = f"""
    You are an expert Cyber Security Analyst. 
    Analyze the following static analysis result of a file and provide a sophisticated, professional summary.
    
    File Type: {analysis_data.get('type')}
    Risk Score: {analysis_data.get('risk_score')}/100
    Verdict: {analysis_data.get('verdict')}
    Findings: {", ".join(analysis_data.get('details', []))}
    
    Please provide your expert opinion in the following format:
    - **Threat Assessment**: (Brief summary)
    - **Technical Impact**: (What could happen)
    - **Recommended Mitigation**: (Action items)
    
    Language: Professional English. Keep it under 200 words.
    """
    
    try:
        # Check if Ollama is reachable
        response = requests.post(f"{ollama_url}/api/generate", 
                                 json={"model": model, "prompt": prompt, "stream": False},
                                 timeout=20)
        if response.status_code == 200:
            return response.json().get('response', "AI Insight: No response from model.")
        return f"AI Insight: Ollama returned status {response.status_code}"
    except Exception as e:
        return f"AI Insight: Local LLM service unreachable (Ollama at {ollama_url}). Make sure Ollama is running on the host."

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
        
        # 3. Generate AI Insight via Local Ollama (Optional)
        analysis['ai_insight'] = generate_ai_insight(analysis)
        
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
                {'title': 'Detection Results', 'content': "\n".join(f"• {d}" for d in analysis['details']) if analysis['details'] else "No suspicious elements found."},
                {'title': 'Triangle AI Insights', 'content': analysis.get('ai_insight', 'No AI insight generated.')}
            ]
        }

        return jsonify(result)

    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

# --------------------------------------------------------------------------
# Cloud Native Security Hub — In-Memory Event Store
# --------------------------------------------------------------------------
import threading

_events = []
_events_lock = threading.Lock()
MAX_EVENTS = 500


@app.route('/api/scan-event', methods=['POST'])
def scan_event():
    """Receive a file + K8s metadata from a DaemonSet scanner."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    node_name = request.form.get('node_name', 'unknown')
    namespace = request.form.get('namespace', 'unknown')
    pod_name = request.form.get('pod_name', 'unknown')
    file_path = request.form.get('file_path', file.filename or 'unknown')

    try:
        bytes_data = file.read()
        sha256 = hashlib.sha256(bytes_data).hexdigest()
        analysis = analyze_file(bytes_data, os.path.basename(file_path))

        # Build AI insight for HIGH RISK only (to save resources)
        ai_insight = ''
        if analysis.get('risk_score', 0) >= 60:
            ai_insight = generate_ai_insight(analysis)

        event = {
            'id': len(_events) + 1,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'node_name': node_name,
            'namespace': namespace,
            'pod_name': pod_name,
            'file_path': file_path,
            'filename': os.path.basename(file_path),
            'sha256': sha256,
            'file_size': len(bytes_data),
            'mime_type': magic.from_buffer(bytes_data, mime=True),
            'type': analysis['type'],
            'risk_score': analysis['risk_score'],
            'verdict': analysis['verdict'],
            'details': analysis['details'],
            'ai_insight': ai_insight,
        }

        with _events_lock:
            _events.insert(0, event)
            if len(_events) > MAX_EVENTS:
                _events.pop()

        return jsonify({'status': 'received', 'event': event})

    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/events', methods=['GET'])
def get_events():
    """Return recent scan events for the Security Hub dashboard."""
    limit = min(int(request.args.get('limit', 50)), MAX_EVENTS)
    verdict_filter = request.args.get('verdict', None)

    with _events_lock:
        filtered = _events
        if verdict_filter:
            filtered = [e for e in _events if e['verdict'] == verdict_filter]
        return jsonify({'events': filtered[:limit], 'total': len(_events)})


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Return aggregated cluster-wide statistics."""
    with _events_lock:
        total = len(_events)
        threats = sum(1 for e in _events if e['verdict'] in ('HIGH RISK', 'MEDIUM RISK'))
        clean = sum(1 for e in _events if e['verdict'] == 'CLEAN')
        high_risk = sum(1 for e in _events if e['verdict'] == 'HIGH RISK')

        # Per-node breakdown
        nodes = {}
        for e in _events:
            n = e['node_name']
            if n not in nodes:
                nodes[n] = {'total': 0, 'threats': 0, 'high_risk': 0}
            nodes[n]['total'] += 1
            if e['verdict'] in ('HIGH RISK', 'MEDIUM RISK'):
                nodes[n]['threats'] += 1
            if e['verdict'] == 'HIGH RISK':
                nodes[n]['high_risk'] += 1

        # Timeline (last 10 events timestamps + scores)
        timeline = [{'t': e['timestamp'], 's': e['risk_score'], 'v': e['verdict']}
                     for e in _events[:30]]

        return jsonify({
            'total_scans': total,
            'threats_detected': threats,
            'high_risk': high_risk,
            'clean_files': clean,
            'active_nodes': len(nodes),
            'nodes': nodes,
            'timeline': timeline,
        })


# --------------------------------------------------------------------------
# eBPF Event Ingestion (from eBPF Tracer DaemonSet)
# --------------------------------------------------------------------------
_ebpf_events = []
_ebpf_lock = threading.Lock()
MAX_EBPF_EVENTS = 1000


@app.route('/api/ebpf-events', methods=['POST'])
def ingest_ebpf_events():
    """Receive batched eBPF security events from the kernel tracer."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data'}), 400

    events = data.get('events', [])
    with _ebpf_lock:
        for evt in events:
            evt['source'] = 'ebpf-tracer'
            evt['node'] = data.get('node', 'unknown')
            _ebpf_events.insert(0, evt)
        while len(_ebpf_events) > MAX_EBPF_EVENTS:
            _ebpf_events.pop()

    return jsonify({'status': 'ok', 'ingested': len(events)})


@app.route('/api/ebpf-events', methods=['GET'])
def get_ebpf_events():
    """Return recent eBPF security events for the dashboard."""
    limit = min(int(request.args.get('limit', 50)), MAX_EBPF_EVENTS)
    severity = request.args.get('severity', None)
    with _ebpf_lock:
        filtered = _ebpf_events
        if severity:
            filtered = [e for e in _ebpf_events if e.get('severity') == severity]
        return jsonify({'events': filtered[:limit], 'total': len(_ebpf_events)})


# --------------------------------------------------------------------------
# Admission Controller Audit (from Admission Webhook)
# --------------------------------------------------------------------------
_admission_events = []
_admission_lock = threading.Lock()
MAX_ADMISSION_EVENTS = 500


@app.route('/api/admission-events', methods=['POST'])
def ingest_admission_event():
    """Receive admission denial audit events from the webhook."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data'}), 400

    data['id'] = len(_admission_events) + 1
    with _admission_lock:
        _admission_events.insert(0, data)
        while len(_admission_events) > MAX_ADMISSION_EVENTS:
            _admission_events.pop()

    return jsonify({'status': 'recorded', 'id': data['id']})


@app.route('/api/admission-events', methods=['GET'])
def get_admission_events():
    """Return recent admission denials for audit dashboard."""
    limit = min(int(request.args.get('limit', 50)), MAX_ADMISSION_EVENTS)
    with _admission_lock:
        return jsonify({'events': _admission_events[:limit], 'total': len(_admission_events)})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
