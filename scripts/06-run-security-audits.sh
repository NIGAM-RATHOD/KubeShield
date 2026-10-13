#!/usr/bin/env bash
# =============================================================================
# 06-run-security-audits.sh
# Executes kube-bench (CIS Kubernetes benchmark) and kubescape compliance audits
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "================================================================="
echo "==> [Phase 5] Running KubeShield Security Scans & Compliance Audits"
echo "================================================================="

# 1. Run kube-bench job
echo "--> Deploying kube-bench CIS benchmark audit Job..."
kubectl delete job kube-bench --ignore-not-found -n default
kubectl apply -f "${ROOT_DIR}/security-scans/kube-bench/kube-bench-job.yaml"

echo "--> Waiting for kube-bench audit job to complete..."
kubectl wait --for=condition=complete job/kube-bench -n default --timeout=120s

echo "--> Kube-bench Audit Results:"
kubectl logs job/kube-bench -n default | head -n 45

# 2. Run Kubescape scan
echo -e "\n--> Running Kubescape framework scans on KubeShield manifests..."
bash "${ROOT_DIR}/security-scans/kubescape/kubescape-scan.sh"

echo "================================================================="
echo "==> Security scans completed! See docs/hardening-benchmarks.md for report."
echo "================================================================="
