# -*- coding: utf-8 -*-
"""
Triangle AI — eBPF-Based Security Tracer
Kernel-level syscall tracing for high-performance container security monitoring.
Uses BCC (BPF Compiler Collection) to attach eBPF probes to critical syscalls.
"""
import os
import sys
import json
import time
import signal
import logging
import requests
import threading
from datetime import datetime
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format='%(asctime)s [eBPF-TRACER] %(message)s')
log = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
ANALYZER_URL = os.environ.get('ANALYZER_URL', 'http://pdf-analyzer-service:5000')
NODE_NAME = os.environ.get('NODE_NAME', 'unknown-node')
REPORT_INTERVAL = int(os.environ.get('REPORT_INTERVAL', '10'))  # seconds
GPU_MONITOR = os.environ.get('GPU_MONITOR_ENABLED', 'false').lower() == 'true'

# Suspicious syscall patterns for container escape / file access
SUSPICIOUS_PATHS = [
    '/etc/shadow', '/etc/passwd', '/root/.ssh',
    '/var/run/secrets/kubernetes.io',
    '/proc/sysrq-trigger', '/proc/kcore',
]

# GPU-specific paths for model weight theft detection
GPU_SENSITIVE_PATHS = [
    '/dev/nvidia',         # Direct GPU device access
    '/proc/driver/nvidia', # NVIDIA driver interface
]

GPU_MODEL_EXTENSIONS = [
    '.bin', '.pt', '.pth', '.safetensors', '.gguf', '.onnx',
    '.h5', '.pb', '.tflite', '.ckpt',
]


# --------------------------------------------------------------------------
# eBPF Program (C code injected into kernel)
# --------------------------------------------------------------------------
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

// Data structure for events sent to userspace
struct event_t {
    u32 pid;
    u32 uid;
    u32 ppid;
    char comm[TASK_COMM_LEN];     // 16 bytes
    char filename[256];
    u64 timestamp_ns;
    u32 syscall_type;             // 0=open, 1=exec, 2=connect, 3=ptrace
    u32 flags;
};

BPF_PERF_OUTPUT(events);
BPF_HASH(pid_filter, u32, u8);

// ─── Trace: openat() ───
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct event_t evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.syscall_type = 0;
    evt.flags = args->flags;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    evt.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    bpf_probe_read_user_str(&evt.filename, sizeof(evt.filename), args->filename);

    events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

// ─── Trace: execve() ───
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event_t evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.syscall_type = 1;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    evt.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    bpf_probe_read_user_str(&evt.filename, sizeof(evt.filename), args->filename);

    events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

// ─── Trace: ptrace() — GPU memory attach / process injection ───
TRACEPOINT_PROBE(syscalls, sys_enter_ptrace) {
    struct event_t evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.syscall_type = 3;
    evt.flags = args->request;  // PTRACE_ATTACH=16, PTRACE_PEEKDATA=2

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    evt.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}
"""


# --------------------------------------------------------------------------
# Event Aggregator
# --------------------------------------------------------------------------
class EventAggregator:
    """Collect and batch eBPF events before reporting to the analyzer."""

    def __init__(self):
        self._lock = threading.Lock()
        self._events = []
        self._stats = defaultdict(int)

    def add(self, event):
        with self._lock:
            self._events.append(event)
            self._stats[event['category']] += 1

    def flush(self):
        with self._lock:
            batch = self._events.copy()
            stats = dict(self._stats)
            self._events.clear()
            self._stats.clear()
        return batch, stats


aggregator = EventAggregator()


# --------------------------------------------------------------------------
# Event Classification
# --------------------------------------------------------------------------
SYSCALL_TYPES = {0: 'file_open', 1: 'process_exec', 2: 'network_connect', 3: 'ptrace'}
PTRACE_ATTACH = 16
PTRACE_PEEKDATA = 2


def classify_event(pid, uid, ppid, comm, filename, syscall_type, flags):
    """Classify an eBPF event into security categories."""
    category = 'info'
    severity = 'low'
    description = ''
    sc = SYSCALL_TYPES.get(syscall_type, 'unknown')

    # --- ptrace-based attacks ---
    if syscall_type == 3:
        if flags in (PTRACE_ATTACH, PTRACE_PEEKDATA):
            category = 'process_injection'
            severity = 'critical'
            description = f'ptrace attach/peek detected (request={flags}) by {comm}[{pid}]'
            if GPU_MONITOR:
                description += ' — possible GPU memory exfiltration attempt'
            return category, severity, description

    # --- File access ---
    if syscall_type == 0:
        # Suspicious host path access
        for sp in SUSPICIOUS_PATHS:
            if filename.startswith(sp):
                category = 'container_escape'
                severity = 'critical'
                description = f'{comm}[{pid}] accessed sensitive path: {filename}'
                return category, severity, description

        # GPU device direct access
        if GPU_MONITOR:
            for gp in GPU_SENSITIVE_PATHS:
                if filename.startswith(gp):
                    category = 'gpu_unauthorized_access'
                    severity = 'high'
                    description = f'{comm}[{pid}] directly accessed GPU device: {filename}'
                    return category, severity, description

            # Model weight file access (potential theft)
            ext = os.path.splitext(filename)[1].lower()
            if ext in GPU_MODEL_EXTENSIONS:
                category = 'model_weight_access'
                severity = 'high'
                description = f'{comm}[{pid}] accessed model weight file: {filename}'
                return category, severity, description

        # K8s secrets access
        if '/var/run/secrets/' in filename:
            category = 'secret_access'
            severity = 'high'
            description = f'{comm}[{pid}] read K8s secret: {filename}'
            return category, severity, description

    # --- Process execution ---
    if syscall_type == 1:
        danger_bins = ['bash', 'sh', 'curl', 'wget', 'nc', 'ncat', 'python', 'perl']
        basename = os.path.basename(filename)
        if basename in danger_bins:
            category = 'suspicious_exec'
            severity = 'medium'
            description = f'{comm}[{pid}] spawned {basename}'
            return category, severity, description

    return category, severity, description


# --------------------------------------------------------------------------
# Callback: invoked by BCC for each eBPF event
# --------------------------------------------------------------------------
def process_event(cpu, data, size):
    """Handle each raw eBPF event from kernel."""
    try:
        event = b["events"].event(data)  # noqa: F821 — injected by BCC
        filename = event.filename.decode('utf-8', errors='replace').rstrip('\x00')
        comm = event.comm.decode('utf-8', errors='replace').rstrip('\x00')

        category, severity, description = classify_event(
            event.pid, event.uid, event.ppid,
            comm, filename, event.syscall_type, event.flags
        )

        if severity in ('medium', 'high', 'critical'):
            evt = {
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'node': NODE_NAME,
                'pid': event.pid,
                'ppid': event.ppid,
                'uid': event.uid,
                'comm': comm,
                'filename': filename,
                'syscall': SYSCALL_TYPES.get(event.syscall_type, 'unknown'),
                'category': category,
                'severity': severity,
                'description': description,
            }
            aggregator.add(evt)

            if severity == 'critical':
                log.warning(f"🚨 CRITICAL: {description}")
            elif severity == 'high':
                log.warning(f"⚠️  HIGH: {description}")
            else:
                log.info(f"🔍 {description}")

    except Exception as e:
        log.error(f"Event processing error: {e}")


# --------------------------------------------------------------------------
# Reporter: periodically sends batched events to the analyzer
# --------------------------------------------------------------------------
def reporter_loop():
    """Flush aggregated events to Triangle AI analyzer every REPORT_INTERVAL seconds."""
    while True:
        time.sleep(REPORT_INTERVAL)
        batch, stats = aggregator.flush()
        if not batch:
            continue

        payload = {
            'source': 'ebpf-tracer',
            'node': NODE_NAME,
            'event_count': len(batch),
            'stats': stats,
            'events': batch[-100:],  # cap at 100 per batch
            'timestamp': datetime.utcnow().isoformat() + 'Z',
        }

        try:
            resp = requests.post(
                f"{ANALYZER_URL}/api/ebpf-events",
                json=payload, timeout=10,
            )
            if resp.status_code == 200:
                log.info(f"📤 Reported {len(batch)} events (stats: {stats})")
            else:
                log.warning(f"Analyzer returned {resp.status_code}")
        except Exception as e:
            log.warning(f"Report failed: {e}")


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main():
    log.info("=" * 60)
    log.info("Triangle AI eBPF Security Tracer Starting")
    log.info(f"  Node:           {NODE_NAME}")
    log.info(f"  Engine:         {ANALYZER_URL}")
    log.info(f"  Report Interval: {REPORT_INTERVAL}s")
    log.info(f"  GPU Monitor:    {GPU_MONITOR}")
    log.info("=" * 60)

    try:
        from bcc import BPF
    except ImportError:
        log.error("BCC (BPF Compiler Collection) not available!")
        log.error("Install: apt-get install bpfcc-tools python3-bpfcc")
        log.error("Or run in the eBPF DaemonSet container which has BCC pre-installed.")
        sys.exit(1)

    global b
    log.info("Loading eBPF program into kernel...")
    b = BPF(text=BPF_PROGRAM)
    log.info("✅ eBPF probes attached: openat, execve, ptrace")

    b["events"].open_perf_buffer(process_event, page_cnt=64)

    # Start reporter thread
    threading.Thread(target=reporter_loop, daemon=True).start()

    log.info("Listening for kernel events...")
    try:
        while True:
            b.perf_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        log.info("Shutting down eBPF tracer...")
    finally:
        b.cleanup()


if __name__ == '__main__':
    main()
