#!/usr/bin/env bash
# =============================================================================
# Calico CNI Installation Script for Kind Cluster
# Installs Calico daemonset to enable full Kubernetes NetworkPolicy enforcement
# =============================================================================
set -euo pipefail

echo "==> Installing Calico CNI v3.28.2 on Kind cluster..."

# Calico manifest with standard IPPool configured for 192.168.0.0/16
CALICO_URL="https://raw.githubusercontent.com/projectcalico/calico/v3.28.2/manifests/calico.yaml"

kubectl apply -f "${CALICO_URL}"

echo "==> Waiting for Calico CNI components to be ready..."
kubectl rollout status daemonset/calico-node -n kube-system --timeout=180s
kubectl rollout status deployment/calico-kube-controllers -n kube-system --timeout=180s

echo "==> Calico CNI is successfully running! NetworkPolicies are now actively enforced."
