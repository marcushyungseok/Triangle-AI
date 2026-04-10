#!/bin/bash
# ============================================
#  NPE Learner — One-Click Kubernetes Deploy
# ============================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NAMESPACE="npe-learner"

echo "=========================================="
echo "  NPE Learner — Kubernetes Deployment"
echo "=========================================="
echo ""

# 1. Check prerequisites
echo "[1/6] Checking prerequisites..."
command -v minikube >/dev/null 2>&1 || { echo "ERROR: minikube not found"; exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo "ERROR: kubectl not found"; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not found"; exit 1; }

# Ensure minikube is running
if ! minikube status | grep -q "Running"; then
  echo "  → Starting minikube..."
  minikube start
fi
echo "  ✓ All prerequisites met"

# 2. Build images using LOCAL Docker (faster)
echo ""
echo "[2/6] Building pdf-analyzer image (local Docker)..."
docker build -t npe-pdf-analyzer:latest "$SCRIPT_DIR/pdf-analyzer"
echo "  ✓ npe-pdf-analyzer:latest built"

echo ""
echo "[3/6] Building dashboard image (local Docker)..."
docker build -t npe-dashboard:latest "$SCRIPT_DIR/dashboard"
echo "  ✓ npe-dashboard:latest built"

# 3. Load images into Minikube
echo ""
echo "[4/6] Loading images into Minikube..."
minikube image load npe-pdf-analyzer:latest
minikube image load npe-dashboard:latest
echo "  ✓ Images loaded into Minikube"

# 4. Deploy to Kubernetes
echo ""
echo "[5/6] Deploying to Kubernetes..."

kubectl apply -f "$SCRIPT_DIR/k8s/namespace.yaml"
kubectl apply -f "$SCRIPT_DIR/k8s/pdf-analyzer.yaml"
kubectl apply -f "$SCRIPT_DIR/k8s/dashboard.yaml"

echo "  ✓ All manifests applied"

# 5. Wait for pods
echo ""
echo "[6/6] Waiting for pods to be ready..."
kubectl wait --for=condition=ready pod -l app=pdf-analyzer -n $NAMESPACE --timeout=120s 2>/dev/null || true
kubectl wait --for=condition=ready pod -l app=dashboard -n $NAMESPACE --timeout=120s 2>/dev/null || true

echo ""
echo "=========================================="
echo "  Deployment Status"
echo "=========================================="
kubectl get pods -n $NAMESPACE
echo ""
kubectl get svc -n $NAMESPACE
echo ""

# Get access URL
echo "=========================================="
echo "  Access Dashboard"
echo "=========================================="
MINIKUBE_IP=$(minikube ip 2>/dev/null || echo "unknown")
echo "  → Dashboard URL: http://$MINIKUBE_IP:30090"
echo ""
echo "  Or run:"
echo "  minikube service dashboard-service -n $NAMESPACE"
echo ""
echo "=========================================="
echo "  Deployment Complete! ✓"
echo "=========================================="
