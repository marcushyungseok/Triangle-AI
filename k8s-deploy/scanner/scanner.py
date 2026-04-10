# -*- coding: utf-8 -*-
"""
Triangle AI — DaemonSet File Scanner
Watches host filesystem for new files and sends them to the analysis engine.
Resolves real K8s namespace/pod info from file paths.
"""
import os
import sys
import time
import json
import requests
import logging
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logging.basicConfig(level=logging.INFO, format='%(asctime)s [SCANNER] %(message)s')
log = logging.getLogger(__name__)

ANALYZER_URL = os.environ.get('ANALYZER_URL', 'http://pdf-analyzer-service:5000')
NODE_NAME = os.environ.get('NODE_NAME', 'unknown-node')
WATCH_PATH = os.environ.get('WATCH_PATH', '/host-fs')
SCAN_EXTENSIONS = {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.docm', '.xlsm',
                   '.js', '.vbs', '.ps1', '.html', '.htm', '.lnk', '.swf'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

# --------------------------------------------------------------------------
# K8s Pod Discovery — resolve namespace/pod from file paths
# --------------------------------------------------------------------------
_pod_cache = []  # list of { namespace, name, uid, volumes }

def refresh_pod_cache():
    """Query K8s API for pods running on this node."""
    global _pod_cache
    try:
        # In-cluster: use the service account token
        token_path = '/var/run/secrets/kubernetes.io/serviceaccount/token'
        ca_path = '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt'
        ns_path = '/var/run/secrets/kubernetes.io/serviceaccount/namespace'

        if not os.path.exists(token_path):
            log.warning("No K8s service account found, using path-based resolution only.")
            return

        with open(token_path) as f:
            token = f.read().strip()

        api_url = 'https://kubernetes.default.svc'
        headers = {'Authorization': f'Bearer {token}'}
        verify = ca_path if os.path.exists(ca_path) else False

        # Get pods on this node across all namespaces
        resp = requests.get(
            f'{api_url}/api/v1/pods?fieldSelector=spec.nodeName={NODE_NAME}',
            headers=headers, verify=verify, timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()
            pods = []
            for item in data.get('items', []):
                meta = item.get('metadata', {})
                pods.append({
                    'namespace': meta.get('namespace', 'unknown'),
                    'name': meta.get('name', 'unknown'),
                    'uid': meta.get('uid', ''),
                })
            _pod_cache = pods
            log.info(f"Pod cache refreshed: {len(pods)} pods on node {NODE_NAME}")
            for p in pods:
                log.info(f"  → {p['namespace']}/{p['name']}")
        else:
            log.warning(f"K8s API returned {resp.status_code}")
    except Exception as e:
        log.warning(f"Pod cache refresh failed: {e}")


def resolve_k8s_context(filepath):
    """
    Resolve namespace/pod from file path.
    
    Strategy:
    1. Path convention: /host-fs/{namespace}/{pod-name}/filename
    2. Known containerd paths: /host-fs/var/lib/kubelet/pods/{uid}/volumes/...
    3. Fallback: use 'host' namespace
    """
    rel = filepath.replace(WATCH_PATH, '').lstrip('/')
    parts = rel.split('/')

    # All known namespaces from pod cache
    known_ns = {p['namespace'] for p in _pod_cache}

    # Strategy 1a: 3+ parts — /host-fs/{namespace}/{pod}/file
    if len(parts) >= 3:
        ns_candidate = parts[0]
        pod_candidate = parts[1]
        if ns_candidate in known_ns:
            for p in _pod_cache:
                if p['namespace'] == ns_candidate and pod_candidate in p['name']:
                    return p['namespace'], p['name']
            return ns_candidate, pod_candidate

    # Strategy 1b: 2 parts — /host-fs/{namespace}/file (pick a pod from that ns)
    if len(parts) >= 2:
        ns_candidate = parts[0]
        if ns_candidate in known_ns:
            ns_pods = [p for p in _pod_cache if p['namespace'] == ns_candidate]
            if ns_pods:
                return ns_candidate, ns_pods[0]['name']
            return ns_candidate, 'unknown-pod'

    # Strategy 2: Kubelet volume path
    # /host-fs/var/lib/kubelet/pods/{uid}/volumes/kubernetes.io~empty-dir/...
    if 'kubelet/pods/' in filepath:
        uid_start = filepath.find('kubelet/pods/') + len('kubelet/pods/')
        uid_end = filepath.find('/', uid_start)
        if uid_end > uid_start:
            uid = filepath[uid_start:uid_end]
            for p in _pod_cache:
                if p['uid'] == uid:
                    return p['namespace'], p['name']

    # Strategy 3: Fallback — check if path contains any known pod name
    for p in _pod_cache:
        if p['name'] in filepath:
            return p['namespace'], p['name']

    return 'host', 'host-filesystem'


# --------------------------------------------------------------------------
# File Watcher
# --------------------------------------------------------------------------
class ThreatFileHandler(FileSystemEventHandler):
    """Handle new file creation events on the watched directory."""

    def __init__(self):
        self._seen = set()

    def on_created(self, event):
        if event.is_directory:
            return
        self._process(event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        self._process(event.src_path)

    def _process(self, filepath):
        ext = os.path.splitext(filepath)[1].lower()
        if ext not in SCAN_EXTENSIONS:
            return

        if filepath in self._seen:
            return
        self._seen.add(filepath)

        time.sleep(0.5)

        try:
            size = os.path.getsize(filepath)
            if size == 0 or size > MAX_FILE_SIZE:
                return

            # Resolve K8s context
            namespace, pod_name = resolve_k8s_context(filepath)

            log.info(f"New file detected: {filepath} ({size} bytes)")
            log.info(f"  K8s context: {namespace}/{pod_name}")

            with open(filepath, 'rb') as f:
                files = {'file': (os.path.basename(filepath), f)}
                data = {
                    'node_name': NODE_NAME,
                    'namespace': namespace,
                    'pod_name': pod_name,
                    'file_path': filepath,
                }
                resp = requests.post(
                    f"{ANALYZER_URL}/api/scan-event",
                    files=files,
                    data=data,
                    timeout=30,
                )

            if resp.status_code == 200:
                result = resp.json().get('event', {})
                verdict = result.get('verdict', 'UNKNOWN')
                score = result.get('risk_score', 0)
                log.info(f"  → Result: {verdict} (score: {score})")
                if verdict in ('HIGH RISK', 'MEDIUM RISK'):
                    log.warning(f"  ⚠ THREAT in {namespace}/{pod_name}: {verdict}")
            else:
                log.error(f"  → Engine returned {resp.status_code}")

        except Exception as e:
            log.error(f"  → Scan failed: {e}")

        def _clear():
            time.sleep(30)
            self._seen.discard(filepath)
        threading.Thread(target=_clear, daemon=True).start()


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main():
    log.info("=" * 60)
    log.info("Triangle AI DaemonSet Scanner Starting")
    log.info(f"  Node:       {NODE_NAME}")
    log.info(f"  Watch Path: {WATCH_PATH}")
    log.info(f"  Engine:     {ANALYZER_URL}")
    log.info("=" * 60)

    if not os.path.isdir(WATCH_PATH):
        log.error(f"Watch path {WATCH_PATH} does not exist!")
        sys.exit(1)

    # Initial pod discovery
    refresh_pod_cache()

    # Periodically refresh pod cache (every 60s)
    def _refresh_loop():
        while True:
            time.sleep(60)
            refresh_pod_cache()
    threading.Thread(target=_refresh_loop, daemon=True).start()

    # Create namespace directories for demo if they don't exist
    for ns in ['apps', 'default', 'monitoring', 'logging']:
        ns_dir = os.path.join(WATCH_PATH, ns)
        if not os.path.exists(ns_dir):
            try:
                os.makedirs(ns_dir, exist_ok=True)
                log.info(f"  Created watch dir: {ns_dir}")
            except PermissionError:
                pass

    handler = ThreatFileHandler()
    observer = Observer()
    observer.schedule(handler, WATCH_PATH, recursive=True)
    observer.start()

    log.info("Watching for file changes...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == '__main__':
    main()

