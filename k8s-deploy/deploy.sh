#!/bin/bash
# ============================================
#  NPE Learner — Universal Kubernetes Deploy
# ============================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NAMESPACE="npe-learner"
K8S_DIR="$SCRIPT_DIR/k8s"

echo "=========================================="
echo "  NPE Learner — Universal Deployment"
echo "=========================================="
echo ""

# 1. Check prerequisites
echo "[1/5] Checking prerequisites..."
command -v kubectl >/dev/null 2>&1 || { echo "ERROR: kubectl not found"; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not found"; exit 1; }

# Ask for Docker Registry
echo ""
echo "Select Deployment mode:"
echo "1) Local (Minikube/Kind) - No push required"
echo "2) Remote (General Cluster) - Push to Registry"
read -p "Enter choice (1 or 2): " DEPLOY_MODE

REGISTRY=""
if [ "$DEPLOY_MODE" == "2" ]; then
    read -p "Enter Docker Registry Username (e.g. your-docker-id): " REGISTRY
    if [ -z "$REGISTRY" ]; then
        echo "ERROR: Registry username is required for remote deployment."
        exit 1
    fi
    FULL_ANALYZER_IMAGE="$REGISTRY/npe-pdf-analyzer:latest"
    FULL_DASHBOARD_IMAGE="$REGISTRY/npe-dashboard:latest"
else
    FULL_ANALYZER_IMAGE="npe-pdf-analyzer:latest"
    FULL_DASHBOARD_IMAGE="npe-dashboard:latest"
fi

# 2. Build images
echo ""
echo "[2/5] Building Docker images..."
docker build -t "$FULL_ANALYZER_IMAGE" "$SCRIPT_DIR/pdf-analyzer"
docker build -t "$FULL_DASHBOARD_IMAGE" "$SCRIPT_DIR/dashboard"
echo "  ✓ Images built: $FULL_ANALYZER_IMAGE, $FULL_DASHBOARD_IMAGE"

# 3. Handle image transport
echo ""
if [ "$DEPLOY_MODE" == "2" ]; then
    echo "[3/5] Pushing images to registry..."
    docker push "$FULL_ANALYZER_IMAGE"
    docker push "$FULL_DASHBOARD_IMAGE"
    echo "  ✓ Images pushed to $REGISTRY"
else
    echo "[3/5] Handling local image transport..."
    if command -v minikube >/dev/null 2>&1 && minikube status | grep -q "Running"; then
        echo "  → Loading images into Minikube..."
        minikube image load "$FULL_ANALYZER_IMAGE"
        minikube image load "$FULL_DASHBOARD_IMAGE"
        echo "  ✓ Images loaded into Minikube"
    else
        echo "  → No running Minikube detected. Assuming images are available locally (Docker Desktop/Kind)."
    fi
fi

# 4. Deploy to Kubernetes
echo ""
echo "[4/5] Deploying to Kubernetes..."

# Create temporary manifests with correct image names
TEMP_DIR=$(mktemp -d)
cp "$K8S_DIR"/*.yaml "$TEMP_DIR/"

# Update image names in temp files if registry is used
if [ "$DEPLOY_MODE" == "2" ]; then
    sed -i.bak "s|image: npe-pdf-analyzer:latest|image: $FULL_ANALYZER_IMAGE|g" "$TEMP_DIR/pdf-analyzer.yaml"
    sed -i.bak "s|image: npe-dashboard:latest|image: $FULL_DASHBOARD_IMAGE|g" "$TEMP_DIR/dashboard.yaml"
fi

kubectl apply -f "$TEMP_DIR/namespace.yaml"
kubectl apply -f "$TEMP_DIR/pdf-analyzer.yaml"
kubectl apply -f "$TEMP_DIR/dashboard.yaml"

echo "  ✓ All manifests applied"

# 5. Wait for pods
echo ""
echo "[5/5] Waiting for pods to be ready..."
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

# Instructions for access
echo "=========================================="
echo "  Access Dashboard"
echo "=========================================="
if [ "$DEPLOY_MODE" == "1" ] && command -v minikube >/dev/null 2>&1; then
    MINIKUBE_IP=$(minikube ip 2>/dev/null || echo "localhost")
    echo "  → URL: http://$MINIKUBE_IP:30090"
else
    echo "  → For Cloud Clusters, use the External IP of dashboard-service."
    echo "  → Command: kubectl get svc dashboard-service -n $NAMESPACE"
fi
echo "=========================================="
echo "  Deployment Complete! ✓"
echo "=========================================="

rm -rf "$TEMP_DIR"
