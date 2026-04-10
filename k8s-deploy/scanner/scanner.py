# -*- coding: utf-8 -*-
"""
Triangle AI — DaemonSet File Scanner
Watches host filesystem for new files and sends them to the analysis engine.
"""
import os
import sys
import time
import requests
import logging
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

        # Debounce: skip if we already scanned this exact path recently
        if filepath in self._seen:
            return
        self._seen.add(filepath)

        # Wait briefly for file write to complete
        time.sleep(0.5)

        try:
            size = os.path.getsize(filepath)
            if size == 0 or size > MAX_FILE_SIZE:
                return

            log.info(f"New file detected: {filepath} ({size} bytes)")

            with open(filepath, 'rb') as f:
                files = {'file': (os.path.basename(filepath), f)}
                data = {
                    'node_name': NODE_NAME,
                    'namespace': 'host',
                    'pod_name': 'host-filesystem',
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
                    log.warning(f"  ⚠ THREAT DETECTED in {filepath}: {verdict}")
            else:
                log.error(f"  → Engine returned {resp.status_code}")

        except Exception as e:
            log.error(f"  → Scan failed: {e}")

        # Allow re-scan after 30s
        def _clear():
            time.sleep(30)
            self._seen.discard(filepath)
        import threading
        threading.Thread(target=_clear, daemon=True).start()


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
