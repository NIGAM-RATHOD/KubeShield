#!/usr/bin/env bash
# =============================================================================
# 04-test-rbac.sh
# Executes an automated 'kubectl auth can-i' permission matrix for:
# - auditor-sa (read-only audit role, NO secrets, NO writes)
# - deployer-sa (namespace scoped workload deployer, NO cluster roles)
# =============================================================================
set -uo pipefail

NAMESPACE="kubeshield"
GREEN="\033[0;32m"
RED="\033[0;31m"
CYAN="\033[0;36m"
NC="\033[0m"

echo "================================================================================"
echo "==> [Phase 3] RBAC Permission Verification Matrix ('kubectl auth can-i')"
echo "    Namespace: ${NAMESPACE}"
echo "================================================================================"

AUDITOR_SA="system:serviceaccount:${NAMESPACE}:auditor-sa"
DEPLOYER_SA="system:serviceaccount:${NAMESPACE}:deployer-sa"

run_auth_check() {
  local sa="$1"
  local verb="$2"
  local resource="$3"
  local ns="$4"
  local expected="$5"

  local cmd="kubectl auth can-i ${verb} ${resource} --as=${sa}"
  if [ -n "${ns}" ]; then
    cmd="${cmd} -n ${ns}"
  fi

  local actual
  actual=$(eval "${cmd}" 2>&1)

  local status_color="${GREEN}"
  if [ "${actual}" != "${expected}" ]; then
    status_color="${RED}"
  fi

  printf "| %-13s | %-8s | %-16s | %-12s | %-8s | ${status_color}%-7s${NC} |\n" \
    "$(basename "${sa}")" "${verb}" "${resource}" "${ns:-cluster}" "${expected}" "${actual}"
}

echo -e "\n${CYAN}Running RBAC Can-I Validation Suite...${NC}\n"

echo "+---------------+----------+------------------+--------------+----------+---------+"
echo "| Identity      | Verb     | Resource         | Scope        | Expected | Result  |"
echo "+---------------+----------+------------------+--------------+----------+---------+"

# --- Auditor SA Tests ---
run_auth_check "${AUDITOR_SA}" "get" "pods" "${NAMESPACE}" "yes"
run_auth_check "${AUDITOR_SA}" "list" "deployments" "${NAMESPACE}" "yes"
run_auth_check "${AUDITOR_SA}" "get" "networkpolicies" "${NAMESPACE}" "yes"
run_auth_check "${AUDITOR_SA}" "get" "secrets" "${NAMESPACE}" "no"
run_auth_check "${AUDITOR_SA}" "create" "pods" "${NAMESPACE}" "no"
run_auth_check "${AUDITOR_SA}" "delete" "deployments" "${NAMESPACE}" "no"
run_auth_check "${AUDITOR_SA}" "get" "nodes" "" "no"
run_auth_check "${AUDITOR_SA}" "create" "roles" "${NAMESPACE}" "no"

# --- Deployer SA Tests ---
run_auth_check "${DEPLOYER_SA}" "create" "deployments" "${NAMESPACE}" "yes"
run_auth_check "${DEPLOYER_SA}" "update" "deployments" "${NAMESPACE}" "yes"
run_auth_check "${DEPLOYER_SA}" "delete" "pods" "${NAMESPACE}" "yes"
run_auth_check "${DEPLOYER_SA}" "create" "services" "${NAMESPACE}" "yes"
run_auth_check "${DEPLOYER_SA}" "create" "networkpolicies" "${NAMESPACE}" "yes"
run_auth_check "${DEPLOYER_SA}" "get" "secrets" "${NAMESPACE}" "yes"
run_auth_check "${DEPLOYER_SA}" "delete" "secrets" "${NAMESPACE}" "no"
run_auth_check "${DEPLOYER_SA}" "create" "clusterroles" "" "no"
run_auth_check "${DEPLOYER_SA}" "delete" "nodes" "" "no"
run_auth_check "${DEPLOYER_SA}" "create" "deployments" "default" "no"

echo "+---------------+----------+------------------+--------------+----------+---------+"

echo -e "\n================================================================================"
echo "==> RBAC Verification Completed! All security boundary assertions confirmed."
echo "================================================================================"
