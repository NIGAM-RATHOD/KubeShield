#!/usr/bin/env bash
# =============================================================================
# 05-setup-localstack-secrets.sh
# 1. Launches LocalStack (KMS + Secrets Manager) via docker-compose
# 2. Creates KMS CMK and KMS-encrypted secret in Secrets Manager
# 3. Installs External Secrets Operator (ESO) via Helm / manifests
# 4. Deploys SecretStore and ExternalSecret
# 5. Verifies synchronized Secret in namespace 'kubeshield'
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
NAMESPACE="kubeshield"

echo "================================================================="
echo "==> [Phase 4] LocalStack, KMS, Secrets Manager & ESO Integration"
echo "================================================================="

# 1. Start LocalStack
echo "--> Starting LocalStack container with KMS and Secrets Manager..."
docker compose -f "${ROOT_DIR}/docker-compose.yml" up -d

echo "--> Waiting for LocalStack to report healthy status..."
for i in {1..30}; do
  if curl -sf http://localhost:4566/_localstack/health | grep -q "\"kms\": \"available\""; then
    echo "    LocalStack is ready and accepting requests!"
    break
  fi
  echo "    Waiting for LocalStack (attempt ${i}/30)..."
  sleep 2
done

# 2. Check if init script ran or execute manually via docker exec
echo "--> Verifying KMS key and encrypted secret creation in LocalStack..."
docker exec kubeshield-localstack bash -c '
  export AWS_DEFAULT_REGION="us-east-1"
  export AWS_ACCESS_KEY_ID="test"
  export AWS_SECRET_ACCESS_KEY="test"

  if ! awslocal secretsmanager describe-secret --secret-id "kubeshield/orders-api/db-credentials" >/dev/null 2>&1; then
    echo "Running initialization script inside container..."
    bash /etc/localstack/init/ready.d/01-init-kms-secrets.sh
  else
    echo "Secret kubeshield/orders-api/db-credentials already provisioned."
  fi
'

# 3. Install External Secrets Operator (ESO) in Kind cluster
echo "--> Installing External Secrets Operator in cluster..."
if command -v helm >/dev/null 2>&1; then
  helm repo add external-secrets https://charts.external-secrets.io || true
  helm repo update
  helm upgrade --install external-secrets external-secrets/external-secrets \
    -n external-secrets --create-namespace \
    --set installCRDs=true \
    --wait --timeout=180s
else
  echo "    Helm not found. Applying External Secrets Operator CRDs and manifests directly..."
  kubectl apply -f https://raw.githubusercontent.com/external-secrets/external-secrets/v0.9.14/deploy/crds/bundle.yaml
  kubectl apply -f https://raw.githubusercontent.com/external-secrets/external-secrets/v0.9.14/deploy/manifests/external-secrets.yaml
  kubectl wait --for=condition=Ready pod -l app.kubernetes.io/name=external-secrets -n external-secrets --timeout=180s
fi

# 4. Deploy LocalStack SecretStore and ExternalSecret
echo "--> Applying SecretStore and ExternalSecret manifests in '${NAMESPACE}'..."
kubectl apply -f "${ROOT_DIR}/deploy/external-secrets/localstack-secret-store.yaml"
kubectl apply -f "${ROOT_DIR}/deploy/external-secrets/orders-api-external-secret.yaml"

# 5. Verify Secret synchronization
echo "--> Waiting for ExternalSecret to synchronize credentials..."
for i in {1..20}; do
  STATUS=$(kubectl get externalsecret orders-api-db-external-secret -n "${NAMESPACE}" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "False")
  if [ "${STATUS}" == "True" ]; then
    echo "    ExternalSecret successfully synchronized!"
    break
  fi
  echo "    Waiting for sync condition (attempt ${i}/20)..."
  sleep 3
done

echo "--> Verifying native Kubernetes Secret created by ESO:"
kubectl get secret orders-api-db-secret -n "${NAMESPACE}" -o yaml

echo "--> Verifying orders-api receives the credentials:"
kubectl rollout restart deployment orders-api -n "${NAMESPACE}"
kubectl rollout status deployment orders-api -n "${NAMESPACE}" --timeout=60s

echo "--> Querying orders-api /api/v1/security-status:"
kubectl exec -n "${NAMESPACE}" frontend -- curl -s http://orders-api:8000/api/v1/security-status | jq .

echo "================================================================="
echo "==> [Phase 4] External Secrets synced successfully!"
echo "================================================================="
