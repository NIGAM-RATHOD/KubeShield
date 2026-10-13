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

# Wait until LocalStack has finished running its ready.d init hooks, so the check below
# does not race the init script and provision the KMS key twice.
echo "--> Waiting for LocalStack and its init hooks to finish..."
LOCALSTACK_READY=false
for i in {1..60}; do
  if curl -sf http://localhost:4566/_localstack/init/ready | grep -qE '"completed": ?true'; then
    LOCALSTACK_READY=true
    echo "    LocalStack is ready and init hooks have completed!"
    break
  fi
  echo "    Waiting for LocalStack (attempt ${i}/60)..."
  sleep 2
done
if [ "${LOCALSTACK_READY}" != "true" ]; then
  echo "ERROR: LocalStack did not become ready in time. Check: docker logs kubeshield-localstack"
  exit 1
fi

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
if ! command -v helm >/dev/null 2>&1; then
  echo "ERROR: Helm is required to install External Secrets Operator. See https://helm.sh/docs/intro/install/"
  exit 1
fi
# Pinned so the external-secrets.io/v1beta1 manifests in deploy/external-secrets/ remain supported
ESO_CHART_VERSION="0.9.14"
helm repo add external-secrets https://charts.external-secrets.io >/dev/null 2>&1 || true
helm repo update external-secrets
helm upgrade --install external-secrets external-secrets/external-secrets \
  --version "${ESO_CHART_VERSION}" \
  -n external-secrets --create-namespace \
  --set installCRDs=true \
  --wait --timeout=180s

# 4. Deploy LocalStack SecretStore and ExternalSecret
echo "--> Applying SecretStore and ExternalSecret manifests in '${NAMESPACE}'..."
kubectl apply -f "${ROOT_DIR}/deploy/external-secrets/localstack-secret-store.yaml"
kubectl apply -f "${ROOT_DIR}/deploy/external-secrets/orders-api-external-secret.yaml"

# 5. Verify Secret synchronization
echo "--> Waiting for ExternalSecret to synchronize credentials..."
if ! kubectl wait externalsecret/orders-api-db-external-secret -n "${NAMESPACE}" \
  --for=condition=Ready --timeout=90s; then
  echo "ERROR: ExternalSecret failed to sync. Inspect with:"
  echo "       kubectl describe externalsecret orders-api-db-external-secret -n ${NAMESPACE}"
  exit 1
fi

# Show metadata and key names only; never print secret values to the terminal or CI logs
echo "--> Verifying native Kubernetes Secret created by ESO (keys only):"
kubectl get secret orders-api-db-secret -n "${NAMESPACE}" \
  -o go-template='{{.metadata.name}}: {{range $k, $v := .data}}{{$k}} {{end}}{{"\n"}}'

echo "--> Verifying orders-api receives the credentials:"
kubectl rollout restart deployment orders-api -n "${NAMESPACE}"
kubectl rollout status deployment orders-api -n "${NAMESPACE}" --timeout=60s

echo "--> Querying orders-api /api/v1/security-status:"
STATUS_JSON=$(kubectl exec -n "${NAMESPACE}" frontend -- curl -s http://orders-api:8000/api/v1/security-status)
if command -v jq >/dev/null 2>&1; then
  echo "${STATUS_JSON}" | jq .
else
  echo "${STATUS_JSON}"
fi

echo "================================================================="
echo "==> [Phase 4] External Secrets synced successfully!"
echo "================================================================="
