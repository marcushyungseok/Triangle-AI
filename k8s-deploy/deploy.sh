#!/bin/bash
# ============================================================
#  Triangle AI — Universal Kubernetes Deploy v0.9.0
#  Includes: Security Hub, eBPF Tracer, Admission Controller,
#            OpenTelemetry Exporter, GPU Security Monitoring
# ============================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NAMESPACE="npe-learner"
K8S_DIR="$SCRIPT_DIR/k8s"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log_step()  { echo -e "\n${BOLD}${CYAN}▶ $1${NC}"; }
log_ok()    { echo -e "  ${GREEN}✓${NC} $1"; }
log_warn()  { echo -e "  ${YELLOW}⚠${NC} $1"; }
log_err()   { echo -e "  ${RED}✗${NC} $1"; }

echo -e "${BOLD}${CYAN}"
cat << 'BANNER'
  ╔══════════════════════════════════════════════════════════╗
  ║  ▲ Triangle AI — Cloud Native Security Platform v0.9   ║
  ║                                                        ║
  ║  Components:                                           ║
  ║   📊 Security Hub Dashboard                            ║
  ║   🔬 Multi-Format Analyzer Engine                      ║
  ║   🔍 File Scanner DaemonSet                            ║
  ║   ⚡ eBPF Kernel Security Tracer                       ║
  ║   🛡️  Admission Controller Webhook                      ║
  ║   📡 OpenTelemetry OTLP Exporter                       ║
  ║   🎮 GPU Security Monitoring                           ║
  ╚══════════════════════════════════════════════════════════╝
BANNER
echo -e "${NC}"

# ──────────────────────────────────────────
# 1. Prerequisites
# ──────────────────────────────────────────
log_step "[1/8] Checking prerequisites..."
command -v kubectl >/dev/null 2>&1 || { log_err "kubectl not found"; exit 1; }
command -v docker >/dev/null 2>&1 || { log_err "docker not found"; exit 1; }
log_ok "kubectl and docker found"

# ──────────────────────────────────────────
# 2. Deployment Mode
# ──────────────────────────────────────────
log_step "[2/8] Select deployment mode"
echo ""
echo "  1) Local (Minikube/Kind) — No push required"
echo "  2) Remote (Cloud Cluster) — Push to Registry"
read -p "  Enter choice (1 or 2): " DEPLOY_MODE

REGISTRY=""
if [ "$DEPLOY_MODE" == "2" ]; then
    read -p "  Enter Docker Registry (e.g. your-docker-id): " REGISTRY
    if [ -z "$REGISTRY" ]; then
        log_err "Registry username is required for remote deployment."
        exit 1
    fi
    IMG_ANALYZER="$REGISTRY/npe-pdf-analyzer:latest"
    IMG_DASHBOARD="$REGISTRY/npe-dashboard:latest"
    IMG_SECURITY_HUB="$REGISTRY/triangle-security-hub:latest"
    IMG_EBPF="$REGISTRY/triangle-ebpf-tracer:latest"
    IMG_ADMISSION="$REGISTRY/triangle-admission-controller:latest"
    IMG_OTEL="$REGISTRY/triangle-otel-exporter:latest"
else
    IMG_ANALYZER="npe-pdf-analyzer:latest"
    IMG_DASHBOARD="npe-dashboard:latest"
    IMG_SECURITY_HUB="triangle-security-hub:latest"
    IMG_EBPF="triangle-ebpf-tracer:latest"
    IMG_ADMISSION="triangle-admission-controller:latest"
    IMG_OTEL="triangle-otel-exporter:latest"
fi

# ──────────────────────────────────────────
# 3. Build Docker Images
# ──────────────────────────────────────────
log_step "[3/8] Building Docker images..."

echo "  → pdf-analyzer..."
docker build -t "$IMG_ANALYZER" "$SCRIPT_DIR/pdf-analyzer" > /dev/null 2>&1
log_ok "pdf-analyzer"

echo "  → dashboard..."
docker build -t "$IMG_DASHBOARD" "$SCRIPT_DIR/dashboard" > /dev/null 2>&1
log_ok "dashboard"

echo "  → security-hub..."
docker build -t "$IMG_SECURITY_HUB" "$SCRIPT_DIR/security-hub" > /dev/null 2>&1
log_ok "security-hub"

echo "  → ebpf-tracer..."
docker build -t "$IMG_EBPF" "$SCRIPT_DIR/ebpf-tracer" > /dev/null 2>&1
log_ok "ebpf-tracer"

echo "  → admission-controller..."
docker build -t "$IMG_ADMISSION" "$SCRIPT_DIR/admission-controller" > /dev/null 2>&1
log_ok "admission-controller"

echo "  → otel-exporter..."
docker build -t "$IMG_OTEL" "$SCRIPT_DIR/otel-exporter" > /dev/null 2>&1
log_ok "otel-exporter"

# ──────────────────────────────────────────
# 4. Image Transport
# ──────────────────────────────────────────
log_step "[4/8] Handling image transport..."

ALL_IMAGES="$IMG_ANALYZER $IMG_DASHBOARD $IMG_SECURITY_HUB $IMG_EBPF $IMG_ADMISSION $IMG_OTEL"

if [ "$DEPLOY_MODE" == "2" ]; then
    echo "  → Pushing images to $REGISTRY..."
    for img in $ALL_IMAGES; do
        docker push "$img" > /dev/null 2>&1
        log_ok "Pushed $img"
    done
else
    if command -v minikube >/dev/null 2>&1 && minikube status 2>/dev/null | grep -q "Running"; then
        echo "  → Loading images into Minikube..."
        for img in $ALL_IMAGES; do
            minikube image load "$img" > /dev/null 2>&1
            log_ok "Loaded $img"
        done
    else
        log_warn "No running Minikube detected. Assuming images are available locally."
    fi
fi

# ──────────────────────────────────────────
# 5. Generate TLS Certs for Admission Controller
# ──────────────────────────────────────────
log_step "[5/8] Setting up Admission Controller TLS..."

CERT_DIR="$SCRIPT_DIR/.certs"
mkdir -p "$CERT_DIR"

if kubectl get secret triangle-admission-tls -n "$NAMESPACE" > /dev/null 2>&1; then
    log_ok "TLS secret already exists, skipping generation"
else
    # Generate self-signed cert for the webhook
    openssl req -x509 -newkey rsa:2048 \
        -keyout "$CERT_DIR/tls.key" -out "$CERT_DIR/tls.crt" \
        -days 365 -nodes \
        -subj "/CN=triangle-admission-controller.$NAMESPACE.svc" \
        > /dev/null 2>&1
    log_ok "TLS certificate generated"

    # Create namespace first (if it doesn't exist)
    kubectl apply -f "$K8S_DIR/namespace.yaml" > /dev/null 2>&1

    # Create TLS secret
    kubectl create secret tls triangle-admission-tls \
        --cert="$CERT_DIR/tls.crt" --key="$CERT_DIR/tls.key" \
        -n "$NAMESPACE" > /dev/null 2>&1
    log_ok "TLS secret created in $NAMESPACE"

    # Inject CA bundle into webhook configuration
    CA_BUNDLE=$(cat "$CERT_DIR/tls.crt" | base64 | tr -d '\n')
    export CA_BUNDLE
fi

# ──────────────────────────────────────────
# 6. Deploy to Kubernetes
# ──────────────────────────────────────────
log_step "[6/8] Deploying to Kubernetes..."

# Create temporary manifests with correct image names
TEMP_DIR=$(mktemp -d)
cp "$K8S_DIR"/*.yaml "$TEMP_DIR/"

# Update image names if registry is used
if [ "$DEPLOY_MODE" == "2" ]; then
    for f in "$TEMP_DIR"/*.yaml; do
        sed -i.bak "s|image: npe-pdf-analyzer:latest|image: $IMG_ANALYZER|g" "$f"
        sed -i.bak "s|image: npe-dashboard:latest|image: $IMG_DASHBOARD|g" "$f"
        sed -i.bak "s|image: triangle-security-hub:latest|image: $IMG_SECURITY_HUB|g" "$f"
        sed -i.bak "s|image: triangle-ebpf-tracer:latest|image: $IMG_EBPF|g" "$f"
        sed -i.bak "s|image: triangle-admission-controller:latest|image: $IMG_ADMISSION|g" "$f"
        sed -i.bak "s|image: triangle-otel-exporter:latest|image: $IMG_OTEL|g" "$f"
    done
fi

# Inject CA bundle into admission controller webhook
if [ -n "$CA_BUNDLE" ]; then
    sed -i.bak "s|caBundle: \"\"|caBundle: \"$CA_BUNDLE\"|g" "$TEMP_DIR/admission-controller.yaml"
fi

# Apply manifests in order
echo "  → Namespace..."
kubectl apply -f "$TEMP_DIR/namespace.yaml" > /dev/null 2>&1
log_ok "Namespace $NAMESPACE"

echo "  → Analysis Engine..."
kubectl apply -f "$TEMP_DIR/pdf-analyzer.yaml" > /dev/null 2>&1
log_ok "PDF Analyzer"

echo "  → Dashboard..."
kubectl apply -f "$TEMP_DIR/dashboard.yaml" > /dev/null 2>&1
log_ok "Dashboard"

echo "  → Security Hub..."
kubectl apply -f "$TEMP_DIR/security-hub.yaml" > /dev/null 2>&1
log_ok "Security Hub"

echo "  → File Scanner DaemonSet..."
kubectl apply -f "$TEMP_DIR/scanner-daemonset.yaml" > /dev/null 2>&1
log_ok "Scanner DaemonSet"

echo "  → eBPF Kernel Tracer..."
kubectl apply -f "$TEMP_DIR/ebpf-tracer-daemonset.yaml" > /dev/null 2>&1
log_ok "eBPF Tracer DaemonSet"

echo "  → Admission Controller Webhook..."
kubectl apply -f "$TEMP_DIR/admission-controller.yaml" > /dev/null 2>&1
log_ok "Admission Controller + ValidatingWebhook"

echo "  → OpenTelemetry Exporter..."
kubectl apply -f "$TEMP_DIR/otel-exporter.yaml" > /dev/null 2>&1
log_ok "OTEL Exporter"

# ──────────────────────────────────────────
# 7. Wait for Pods
# ──────────────────────────────────────────
log_step "[7/8] Waiting for pods to be ready..."

kubectl wait --for=condition=ready pod -l app=pdf-analyzer -n $NAMESPACE --timeout=120s 2>/dev/null || true
kubectl wait --for=condition=ready pod -l app=dashboard -n $NAMESPACE --timeout=120s 2>/dev/null || true
kubectl wait --for=condition=ready pod -l app=security-hub -n $NAMESPACE --timeout=120s 2>/dev/null || true
kubectl wait --for=condition=ready pod -l app=triangle-admission-controller -n $NAMESPACE --timeout=60s 2>/dev/null || true
kubectl wait --for=condition=ready pod -l app=triangle-otel-exporter -n $NAMESPACE --timeout=60s 2>/dev/null || true

echo ""
kubectl get pods -n $NAMESPACE
echo ""
kubectl get svc -n $NAMESPACE

# ──────────────────────────────────────────
# 8. Access Information
# ──────────────────────────────────────────
log_step "[8/8] Deployment Complete!"

if [ "$DEPLOY_MODE" == "1" ] && command -v minikube >/dev/null 2>&1; then
    MINIKUBE_IP=$(minikube ip 2>/dev/null || echo "localhost")
else
    MINIKUBE_IP="<EXTERNAL_IP>"
fi

echo -e "${BOLD}${GREEN}"
cat << DONE

  ╔══════════════════════════════════════════════════════════╗
  ║  ▲ Triangle AI v0.9.0 — Deployment Complete! ✓         ║
  ║                                                        ║
  ║  📊 Dashboard:     http://${MINIKUBE_IP}:30090           
  ║  🔐 Security Hub:  http://${MINIKUBE_IP}:30091           
  ║                                                        ║
  ║  Components deployed:                                  ║
  ║   ✅ Multi-Format Analyzer Engine                      ║
  ║   ✅ File Upload Dashboard                             ║
  ║   ✅ Cloud Native Security Hub                         ║
  ║   ✅ File Scanner DaemonSet                            ║
  ║   ✅ eBPF Kernel Security Tracer                       ║
  ║   ✅ Admission Controller Webhook                      ║
  ║   ✅ OpenTelemetry OTLP Exporter                       ║
  ║   ✅ GPU Security Monitoring                           ║
  ║                                                        ║
  ║  Port-forward commands:                                ║
  ║   kubectl port-forward svc/security-hub-service        ║
  ║     -n npe-learner 30091:3001                          ║
  ╚══════════════════════════════════════════════════════════╝

DONE
echo -e "${NC}"

rm -rf "$TEMP_DIR"
