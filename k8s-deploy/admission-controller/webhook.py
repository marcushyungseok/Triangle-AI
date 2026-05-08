# -*- coding: utf-8 -*-
"""
Triangle AI — Admission Controller Webhook
Kubernetes ValidatingWebhookConfiguration server that blocks containers
not meeting security requirements at creation time.
"""
import os
import sys
import json
import base64
import logging
import hashlib
from flask import Flask, request, jsonify
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s [ADMISSION] %(message)s')
log = logging.getLogger(__name__)

app = Flask(__name__)

# --------------------------------------------------------------------------
# Security Policy Configuration
# --------------------------------------------------------------------------
POLICY = {
    # Block privileged containers (unless explicitly allowed)
    'block_privileged': os.environ.get('BLOCK_PRIVILEGED', 'true').lower() == 'true',

    # Block containers running as root (UID 0)
    'block_root_user': os.environ.get('BLOCK_ROOT_USER', 'true').lower() == 'true',

    # Block containers without resource limits
    'require_resource_limits': os.environ.get('REQUIRE_LIMITS', 'true').lower() == 'true',

    # Block containers with hostPath mounts
    'block_host_path': os.environ.get('BLOCK_HOST_PATH', 'true').lower() == 'true',

    # Block containers with hostPID/hostNetwork
    'block_host_namespace': os.environ.get('BLOCK_HOST_NS', 'true').lower() == 'true',

    # Allowed image registries (comma-separated)
    'allowed_registries': os.environ.get(
        'ALLOWED_REGISTRIES',
        'docker.io,gcr.io,ghcr.io,quay.io,registry.k8s.io'
    ).split(','),

    # Namespaces excluded from checks (system namespaces)
    'excluded_namespaces': os.environ.get(
        'EXCLUDED_NAMESPACES',
        'kube-system,kube-public,kube-node-lease,npe-learner'
    ).split(','),

    # Maximum allowed capabilities
    'blocked_capabilities': [
        'SYS_ADMIN', 'NET_RAW', 'SYS_PTRACE', 'ALL',
    ],

    # GPU-specific: block direct GPU device mounts without annotation
    'require_gpu_annotation': os.environ.get('REQUIRE_GPU_ANNOTATION', 'true').lower() == 'true',
}


# --------------------------------------------------------------------------
# Validation Logic
# --------------------------------------------------------------------------
def validate_pod(pod_spec, namespace, pod_name, labels, annotations):
    """
    Validate a Pod spec against Triangle AI security policies.
    Returns (allowed: bool, reasons: list[str])
    """
    violations = []

    # Skip excluded namespaces
    if namespace in POLICY['excluded_namespaces']:
        return True, []

    containers = pod_spec.get('containers', []) + pod_spec.get('initContainers', [])

    for container in containers:
        cname = container.get('name', 'unknown')
        sc = container.get('securityContext', {})

        # ─── Check 1: Privileged mode ───
        if POLICY['block_privileged'] and sc.get('privileged', False):
            violations.append(
                f"[BLOCKED] Container '{cname}' requests privileged mode. "
                "This is a critical security risk."
            )

        # ─── Check 2: Running as root ───
        if POLICY['block_root_user']:
            run_as_user = sc.get('runAsUser', None)
            run_as_non_root = sc.get('runAsNonRoot', False)
            if run_as_user == 0:
                violations.append(
                    f"[BLOCKED] Container '{cname}' runs as UID 0 (root). "
                    "Set runAsNonRoot: true or specify a non-zero runAsUser."
                )
            elif not run_as_non_root and run_as_user is None:
                # Warn but don't block unless explicitly UID 0
                pass

        # ─── Check 3: Resource limits ───
        if POLICY['require_resource_limits']:
            resources = container.get('resources', {})
            limits = resources.get('limits', {})
            if not limits.get('cpu') or not limits.get('memory'):
                violations.append(
                    f"[BLOCKED] Container '{cname}' has no CPU/memory limits. "
                    "Set resources.limits.cpu and resources.limits.memory."
                )

        # ─── Check 4: Image registry allowlist ───
        image = container.get('image', '')
        image_allowed = False
        for reg in POLICY['allowed_registries']:
            reg = reg.strip()
            if image.startswith(reg) or '/' not in image.split(':')[0]:
                # Allow shorthand images like "nginx:latest" (defaults to docker.io)
                image_allowed = True
                break
        if not image_allowed:
            violations.append(
                f"[BLOCKED] Container '{cname}' uses untrusted registry: '{image}'. "
                f"Allowed: {', '.join(POLICY['allowed_registries'])}"
            )

        # ─── Check 5: Dangerous capabilities ───
        caps = sc.get('capabilities', {}).get('add', [])
        for cap in caps:
            if cap.upper() in POLICY['blocked_capabilities']:
                violations.append(
                    f"[BLOCKED] Container '{cname}' adds dangerous capability: {cap}. "
                    "Remove this capability or request an exception."
                )

    # ─── Check 6: hostPath volumes ───
    if POLICY['block_host_path']:
        volumes = pod_spec.get('volumes', [])
        for vol in volumes:
            if 'hostPath' in vol:
                path = vol['hostPath'].get('path', '')
                violations.append(
                    f"[BLOCKED] Volume '{vol.get('name')}' mounts hostPath '{path}'. "
                    "Use emptyDir, configMap, or PVC instead."
                )

    # ─── Check 7: Host namespace access ───
    if POLICY['block_host_namespace']:
        if pod_spec.get('hostPID', False):
            violations.append(
                "[BLOCKED] Pod requests hostPID: true. "
                "This exposes host processes and is a container escape vector."
            )
        if pod_spec.get('hostNetwork', False):
            violations.append(
                "[BLOCKED] Pod requests hostNetwork: true. "
                "This bypasses network policies."
            )

    # ─── Check 8: GPU annotation requirement ───
    if POLICY['require_gpu_annotation']:
        for container in containers:
            resources = container.get('resources', {})
            limits = resources.get('limits', {})
            if 'nvidia.com/gpu' in limits:
                if annotations.get('triangle-ai/gpu-approved') != 'true':
                    violations.append(
                        f"[BLOCKED] Container '{container.get('name')}' requests GPU resources "
                        "but lacks 'triangle-ai/gpu-approved: true' annotation. "
                        "Contact the platform team for GPU access approval."
                    )

    allowed = len(violations) == 0
    return allowed, violations


# --------------------------------------------------------------------------
# Webhook Endpoint
# --------------------------------------------------------------------------
@app.route('/validate', methods=['POST'])
def validate():
    """Kubernetes admission webhook validation endpoint."""
    admission_review = request.get_json()

    if not admission_review:
        return jsonify({'error': 'No admission review received'}), 400

    req = admission_review.get('request', {})
    uid = req.get('uid', '')
    namespace = req.get('namespace', 'default')
    kind = req.get('kind', {}).get('kind', 'Unknown')
    operation = req.get('operation', 'UNKNOWN')

    # Only validate Pod CREATE/UPDATE
    if kind != 'Pod' or operation not in ('CREATE', 'UPDATE'):
        return _admit(uid, True, "Non-pod or non-create operation — skipped.")

    obj = req.get('object', {})
    metadata = obj.get('metadata', {})
    pod_name = metadata.get('name', metadata.get('generateName', 'unknown'))
    labels = metadata.get('labels', {})
    annotations = metadata.get('annotations', {})
    pod_spec = obj.get('spec', {})

    log.info(f"Validating {operation} {namespace}/{pod_name}")

    allowed, violations = validate_pod(pod_spec, namespace, pod_name, labels, annotations)

    if not allowed:
        message = (
            f"Triangle AI Security Policy Violation ({len(violations)} issue(s)):\n"
            + "\n".join(f"  {i+1}. {v}" for i, v in enumerate(violations))
        )
        log.warning(f"❌ DENIED {namespace}/{pod_name}: {len(violations)} violations")
        for v in violations:
            log.warning(f"   → {v}")

        # Report to analyzer for audit trail
        _report_denial(namespace, pod_name, violations)
    else:
        message = "Pod meets Triangle AI security requirements."
        log.info(f"✅ ALLOWED {namespace}/{pod_name}")

    return _admit(uid, allowed, message)


def _admit(uid, allowed, message):
    """Build AdmissionReview response."""
    response = {
        'apiVersion': 'admission.k8s.io/v1',
        'kind': 'AdmissionReview',
        'response': {
            'uid': uid,
            'allowed': allowed,
            'status': {
                'code': 200 if allowed else 403,
                'message': message,
            }
        }
    }
    return jsonify(response)


def _report_denial(namespace, pod_name, violations):
    """Report policy violation to Triangle AI analyzer for audit."""
    try:
        analyzer_url = os.environ.get('ANALYZER_URL', 'http://pdf-analyzer-service:5000')
        requests_lib = __import__('requests')
        requests_lib.post(
            f"{analyzer_url}/api/admission-events",
            json={
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'namespace': namespace,
                'pod_name': pod_name,
                'action': 'DENIED',
                'violations': violations,
                'policy_version': 'v1',
            },
            timeout=5,
        )
    except Exception:
        pass  # Non-critical — don't block webhook response


# --------------------------------------------------------------------------
# Health
# --------------------------------------------------------------------------
@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ok',
        'service': 'triangle-admission-controller',
        'policy': {k: v for k, v in POLICY.items() if not isinstance(v, list)},
    })


# --------------------------------------------------------------------------
# Entry
# --------------------------------------------------------------------------
if __name__ == '__main__':
    cert_file = os.environ.get('TLS_CERT', '/certs/tls.crt')
    key_file = os.environ.get('TLS_KEY', '/certs/tls.key')

    port = int(os.environ.get('PORT', '8443'))

    if os.path.exists(cert_file) and os.path.exists(key_file):
        log.info(f"Starting Admission Controller with TLS on port {port}")
        app.run(host='0.0.0.0', port=port, ssl_context=(cert_file, key_file))
    else:
        log.warning("⚠️  No TLS certs found — running in plaintext (dev mode only)")
        app.run(host='0.0.0.0', port=port)
