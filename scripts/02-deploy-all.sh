#!/usr/bin/env bash
# =============================================================================
# 02-deploy-all.sh
# Deploys namespaces with PSA restricted, RBAC, NetworkPolicies, and applications
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "================================================================="
echo "==> Deploying KubeShield Hardened Security Architecture..."
echo "================================================================="

# 1. Build orders-api container image and load into kind
echo "--> Building orders-api container image..."
docker build -t orders-api:latest "${ROOT_DIR}/apps/orders-api"
echo "--> Loading orders-api image into Kind cluster..."
kind load docker-image orders-api:latest --name kubeshield

# 2. Deploy Namespaces with PSA (Restricted Profile)
echo "--> Applying Namespaces with Pod Security Admission restricted labels..."
kubectl apply -f "${ROOT_DIR}/deploy/namespaces/00-namespaces.yaml"

# 3. Disable automount on default ServiceAccounts
echo "--> Hardening default ServiceAccounts (automountServiceAccountToken: false)..."
kubectl apply -f "${ROOT_DIR}/deploy/namespaces/01-default-sa-hardening.yaml"

# 4. Deploy RBAC (ServiceAccounts, Auditor Role, Deployer Role)
echo "--> Applying RBAC roles and bindings..."
kubectl apply -f "${ROOT_DIR}/deploy/rbac/01-serviceaccounts.yaml"
kubectl apply -f "${ROOT_DIR}/deploy/rbac/02-auditor-role.yaml"
kubectl apply -f "${ROOT_DIR}/deploy/rbac/03-deployer-role.yaml"

# 5. Apply Zero-Trust NetworkPolicies
echo "--> Applying NetworkPolicies (Default-Deny, DNS Egress, Frontend-to-Orders Ingress)..."
kubectl apply -f "${ROOT_DIR}/deploy/network-policies/00-default-deny-all.yaml"
kubectl apply -f "${ROOT_DIR}/deploy/network-policies/01-allow-dns.yaml"
kubectl apply -f "${ROOT_DIR}/deploy/network-policies/02-allow-frontend-to-orders.yaml"

# 6. Deploy Workloads (orders-api, frontend client pod, rogue probe pod)
echo "--> Deploying orders-api microservice, frontend pod, and rogue probe pod..."
kubectl apply -f "${ROOT_DIR}/deploy/apps/orders-api.yaml"
kubectl apply -f "${ROOT_DIR}/deploy/apps/frontend-pod.yaml"
kubectl apply -f "${ROOT_DIR}/deploy/apps/rogue-pod.yaml"

echo "--> Waiting for pods to reach Ready status in namespace 'kubeshield'..."
kubectl wait --for=condition=Ready pod -l app.kubernetes.io/name=orders-api -n kubeshield --timeout=120s
kubectl wait --for=condition=Ready pod/frontend -n kubeshield --timeout=120s
kubectl wait --for=condition=Ready pod/rogue -n kubeshield --timeout=120s

kubectl get pods -n kubeshield -o wide

echo "================================================================="
echo "==> All KubeShield workloads deployed and healthy!"
echo "================================================================="
