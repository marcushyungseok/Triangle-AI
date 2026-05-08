# Release Notes

## 🚀 v0.2.0 — Advanced Security & GPU Protection

### ⚡ eBPF-Based Kernel Security Tracing
- **Kernel-level syscall monitoring**: Attaches eBPF probes to `openat`, `execve`, and `ptrace` syscalls for zero-overhead security tracing.
- **Container escape detection**: Monitors access to sensitive host paths (`/etc/shadow`, `/proc/kcore`, K8s secrets).
- **DaemonSet deployment**: Runs on every node for full cluster coverage.
- **Batched event reporting**: Aggregates events and reports to the analysis engine every 10 seconds.

### 🛡️ Admission Controller Webhook
- **Preventive security enforcement**: Blocks non-compliant containers at Kubernetes API level before creation.
- **8 configurable policies**: Privileged mode, root user, resource limits, hostPath, host namespace, image registry, dangerous capabilities, and GPU annotation requirements.
- **Audit trail**: All denied pod creation attempts are logged to `/api/admission-events`.
- **Fail-open design**: Cluster operations continue even if the webhook is temporarily unavailable.

### 📡 OpenTelemetry Integration
- **OTLP export**: All security events exported as traces, metrics, and structured logs.
- **Grafana-native**: Direct integration with Grafana Tempo (traces), Mimir (metrics), and Loki (logs).
- **Multi-backend**: Compatible with Jaeger, Datadog, New Relic, Splunk via standard OTLP protocol.
- **Custom metrics**: `triangle.security.scans.total`, `triangle.security.threats.total`, `triangle.security.risk_score`.

### 🎮 GPU Security Monitoring
- **GPU device access monitoring**: eBPF tracing of `/dev/nvidia*` and `/proc/driver/nvidia` file opens.
- **Model weight theft detection**: Monitors access to `.safetensors`, `.pt`, `.gguf`, `.onnx`, `.bin` files.
- **GPU memory exfiltration defense**: Detects `ptrace(PTRACE_ATTACH/PEEKDATA)` on GPU-using processes.
- **Admission-level GPU gating**: Blocks pods requesting `nvidia.com/gpu` without `triangle-ai/gpu-approved` annotation.

### 🔌 New API Endpoints
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/ebpf-events` | GET/POST | eBPF kernel security events |
| `/api/admission-events` | GET/POST | Admission controller audit log |

---

## 🚀 v0.1.0 — Initial Release

### ✨ Key Features
- **Multi-Format Analysis**: Supports deep static inspection for PDF, MS Office, JavaScript, HTML, LNK, and SWF files.
- **Advanced Backend Engine**: Integrated specialized tools like `oletools` for macro detection and custom regex-based scanners.
- **Premium Dashboard**: Grafana-inspired dark theme UI featuring real-time risk scoring, radar charts, and detailed threat reports.
- **Universal K8s Deployment**: One-click deployment script (`deploy.sh`) supporting both local Minikube and remote cloud clusters.
- **Distributed Architecture**: Master-Slave cluster design using XMLRPC for high-performance parallel file parsing and training.
- **Machine Learning Integration**: TensorFlow-based FNN model for intelligent "Benign vs Malicious" classification.
- **Cloud Native Security Hub**: DaemonSet-based real-time cluster monitoring with K8s context-aware threat detection.
- **AI-Powered Analysis**: Ollama LLM integration for automated threat assessment and mitigation reports.

### 📦 Deployment
- Version: `v0.2.0`
- GitHub Repository: [Triangle-AI](https://github.com/marcushyungseok/Triangle-AI)
- License: Apache 2.0
