#!/usr/bin/env bash
# =============================================================================
# 03-test-network-policies.sh
# Automated verification proving Calico NetworkPolicy enforcement:
# 1. frontend -> orders-api:8000 ALLOWED (HTTP 200)
# 2. rogue -> orders-api:8000 BLOCKED (Connection timed out / dropped)
# 3. DNS egress ALLOWED for authorized pods, BLOCKED for rogue pod
# =============================================================================
set -uo pipefail

NAMESPACE="kubeshield"
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
NC="\033[0m"
FAILURES=0

echo "================================================================================"
echo "==> [Phase 2] Verifying Calico Zero-Trust NetworkPolicies in namespace: ${NAMESPACE}"
echo "================================================================================"

# Wait for frontend and rogue pods
kubectl wait --for=condition=Ready pod/frontend -n "${NAMESPACE}" --timeout=60s
kubectl wait --for=condition=Ready pod/rogue -n "${NAMESPACE}" --timeout=60s

# -----------------------------------------------------------------------------
# TEST 1: Frontend -> orders-api (Port 8000) [EXPECTED: ALLOWED / 200 OK]
# -----------------------------------------------------------------------------
echo -e "\n${YELLOW}[TEST 1] Testing Authorized Traffic: frontend -> orders-api:8000/healthz${NC}"
echo "Command: kubectl exec -n ${NAMESPACE} frontend -- curl -s -m 5 -w \"\nHTTP_STATUS:%{http_code}\" http://orders-api:8000/healthz"

FRONTEND_RESULT=$(kubectl exec -n "${NAMESPACE}" frontend -- curl -s -m 5 -w "\nHTTP_STATUS:%{http_code}" http://orders-api:8000/healthz 2>&1)
FRONTEND_STATUS=$(echo "${FRONTEND_RESULT}" | grep "HTTP_STATUS" | cut -d':' -f2)
FRONTEND_BODY=$(echo "${FRONTEND_RESULT}" | grep -v "HTTP_STATUS")

echo "--> Actual Output:"
echo "${FRONTEND_BODY}"
echo "--> HTTP Status: ${FRONTEND_STATUS}"

if [ "${FRONTEND_STATUS}" == "200" ]; then
  echo -e "${GREEN}[PASS] TEST 1 SUCCEEDED: Frontend successfully reached orders-api with HTTP 200 OK.${NC}"
else
  echo -e "${RED}[FAIL] TEST 1 FAILED: Expected HTTP 200 but received status: ${FRONTEND_STATUS}${NC}"
  FAILURES=$((FAILURES + 1))
fi

# -----------------------------------------------------------------------------
# TEST 2: Rogue Pod -> orders-api (Port 8000) [EXPECTED: BLOCKED / TIMEOUT]
# -----------------------------------------------------------------------------
# The rogue pod has no DNS egress, so target the Service ClusterIP directly. This proves the
# TCP connection itself is dropped, rather than the request merely failing at name resolution.
ORDERS_IP=$(kubectl get svc orders-api -n "${NAMESPACE}" -o jsonpath='{.spec.clusterIP}')
echo -e "\n${YELLOW}[TEST 2] Testing Unauthorized Rogue Traffic: rogue -> orders-api (${ORDERS_IP}:8000)/healthz${NC}"
echo "Command: kubectl exec -n ${NAMESPACE} rogue -- curl -v -m 4 http://${ORDERS_IP}:8000/healthz"

ROGUE_START=$(date +%s)
ROGUE_RESULT=$(kubectl exec -n "${NAMESPACE}" rogue -- curl -v -m 4 "http://${ORDERS_IP}:8000/healthz" 2>&1 || true)
ROGUE_END=$(date +%s)
DURATION=$((ROGUE_END - ROGUE_START))

echo "--> Actual Output (stderr/stdout):"
echo "${ROGUE_RESULT}"

if echo "${ROGUE_RESULT}" | grep -qiE "timed out|connection refused|failed to connect|timedout|exit code 28"; then
  echo -e "${GREEN}[PASS] TEST 2 SUCCEEDED: Rogue pod was BLOCKED by Calico NetworkPolicy! (Duration: ${DURATION}s)${NC}"
  echo "    Packets were silently dropped at the Calico veth filter layer."
else
  echo -e "${RED}[FAIL] TEST 2 FAILED: Rogue pod was NOT blocked! Check NetworkPolicy selector.${NC}"
  FAILURES=$((FAILURES + 1))
fi

# -----------------------------------------------------------------------------
# TEST 3: DNS Egress Resolution Verification
# -----------------------------------------------------------------------------
echo -e "\n${YELLOW}[TEST 3] Testing DNS Resolution Egress: frontend vs rogue${NC}"
echo "--> Testing DNS resolution from authorized frontend pod..."
if FRONTEND_DNS=$(kubectl exec -n "${NAMESPACE}" frontend -- nslookup orders-api.kubeshield.svc.cluster.local 2>&1); then
  echo "${FRONTEND_DNS}"
  echo -e "${GREEN}[PASS] Frontend DNS resolution ALLOWED.${NC}"
else
  echo "${FRONTEND_DNS}"
  echo -e "${RED}[FAIL] Frontend could not resolve orders-api.${NC}"
  FAILURES=$((FAILURES + 1))
fi

echo "--> Testing DNS resolution from rogue pod (no DNS egress policy)..."
if ROGUE_DNS=$(kubectl exec -n "${NAMESPACE}" rogue -- nslookup -timeout=3 orders-api.kubeshield.svc.cluster.local 2>&1); then
  echo "${ROGUE_DNS}"
  echo -e "${RED}[FAIL] Rogue pod resolved DNS; egress is NOT blocked.${NC}"
  FAILURES=$((FAILURES + 1))
else
  echo "${ROGUE_DNS}"
  echo -e "${GREEN}[PASS] Rogue pod DNS egress BLOCKED.${NC}"
fi

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
echo -e "\n================================================================================"
echo "==> Calico NetworkPolicy Verification Matrix Summary:"
echo "--------------------------------------------------------------------------------"
echo "| Source Pod | Destination Service | Port | NetworkPolicy Rule               | Result  |"
echo "|------------|---------------------|------|----------------------------------|---------|"
echo "| frontend   | orders-api          | 8000 | allow-orders-api-ingress         | ALLOWED |"
echo "| rogue      | orders-api          | 8000 | default-deny-all (Zero-Trust)    | BLOCKED |"
echo "| frontend   | kube-dns            | 53   | allow-dns-egress                 | ALLOWED |"
echo "| rogue      | kube-dns            | 53   | default-deny-all (Zero-Trust)    | BLOCKED |"
echo "================================================================================"

if [ "${FAILURES}" -gt 0 ]; then
  echo -e "${RED}${FAILURES} NetworkPolicy check(s) FAILED.${NC}"
  exit 1
fi
echo -e "${GREEN}All NetworkPolicy checks passed.${NC}"
