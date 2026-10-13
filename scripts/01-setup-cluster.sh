#!/usr/bin/env bash
# =============================================================================
# 01-setup-cluster.sh
# Creates Kind cluster with disabled default CNI and installs Calico CNI
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "================================================================="
echo "==> [Phase 1] Provisioning Kind Cluster with Calico CNI..."
echo "================================================================="

# 1. Verify requirements
for cmd in kind kubectl docker; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "ERROR: Required command '${cmd}' is not found in PATH."
    exit 1
  fi
done

# 2. Check if cluster already exists
if kind get clusters 2>/dev/null | grep -q "^kubeshield$"; then
  echo "Cluster 'kubeshield' already exists. Deleting to ensure clean state..."
  kind delete cluster --name kubeshield
fi

# 3. Create Kind cluster
echo "--> Creating Kind cluster 'kubeshield' from deploy/kind/kind-calico.yaml..."
kind create cluster --config "${ROOT_DIR}/deploy/kind/kind-calico.yaml"

# 4. Install Calico CNI
echo "--> Deploying Calico CNI for NetworkPolicy enforcement..."
bash "${ROOT_DIR}/deploy/cni/install-calico.sh"

echo "--> Verifying cluster nodes are in Ready status..."
kubectl wait --for=condition=Ready nodes --all --timeout=120s
kubectl get nodes -o wide

echo "================================================================="
echo "==> [Phase 1] Kind Cluster with Calico CNI is Ready!"
echo "================================================================="
