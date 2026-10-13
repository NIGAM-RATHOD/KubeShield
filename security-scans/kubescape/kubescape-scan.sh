#!/usr/bin/env bash
# =============================================================================
# Kubescape Security Scan Runner
# Scans manifests and running cluster for compliance with NSA-CISA and MITRE ATT&CK
# =============================================================================
set -euo pipefail

echo "==> Running Kubescape Compliance Scan across KubeShield manifests..."

OUTPUT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(cd "${OUTPUT_DIR}/../../deploy" && pwd)"
mkdir -p "${OUTPUT_DIR}/reports"

# Scan the deploy directory using NSA framework
echo "--> Scanning deploy/ manifests against NSA-CISA framework..."
if command -v kubescape >/dev/null 2>&1; then
  kubescape scan framework nsa "${DEPLOY_DIR}" \
    --format json \
    --output "${OUTPUT_DIR}/reports/nsa-cisa-report.json" \
    --compliance-threshold 80 || true

  kubescape scan framework mitre "${DEPLOY_DIR}" \
    --format json \
    --output "${OUTPUT_DIR}/reports/mitre-report.json" || true

  kubescape scan "${DEPLOY_DIR}" \
    --format pretty-printer
else
  echo "[INFO] kubescape CLI is not installed in the local environment."
  echo "       To install: curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | bash"
  echo "       Pre-calculated benchmark audit reports are available in docs/hardening-benchmarks.md."
fi
