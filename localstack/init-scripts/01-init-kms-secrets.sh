#!/usr/bin/env bash
# =============================================================================
# LocalStack Initialization Script
# Runs automatically upon LocalStack startup (mounted at /etc/localstack/init/ready.d)
# Creates a KMS customer managed key and a KMS-encrypted secret in Secrets Manager.
# Idempotent: safe to re-run against an already-initialized LocalStack instance.
#
# NOTE: The credentials below are throwaway demo values for a local emulator only.
# =============================================================================
set -euo pipefail

export AWS_DEFAULT_REGION="us-east-1"
export AWS_ACCESS_KEY_ID="test"
export AWS_SECRET_ACCESS_KEY="test"

KEY_ALIAS="alias/kubeshield-orders-key"
SECRET_NAME="kubeshield/orders-api/db-credentials"

echo "================================================================="
echo "==> [LocalStack Init] Provisioning KMS Key and Secrets..."
echo "================================================================="

# 1. Create KMS Customer Managed Key (reuse it if the alias already exists)
if KEY_ID=$(awslocal kms describe-key --key-id "${KEY_ALIAS}" \
    --query "KeyMetadata.KeyId" --output text 2>/dev/null); then
  echo "--> KMS key ${KEY_ALIAS} already exists (${KEY_ID}); skipping creation."
else
  echo "--> Creating KMS Customer Managed Key (CMK)..."
  KEY_ID=$(awslocal kms create-key \
    --description "KubeShield Orders API Encryption Key" \
    --key-usage "ENCRYPT_DECRYPT" \
    --key-spec "SYMMETRIC_DEFAULT" \
    --tags TagKey=Project,TagValue=KubeShield TagKey=Environment,TagValue=LocalStack \
    --query "KeyMetadata.KeyId" --output text)
  echo "    KMS Key Created: ${KEY_ID}"

  # 2. Create KMS Alias
  echo "--> Creating KMS Alias '${KEY_ALIAS}'..."
  awslocal kms create-alias --alias-name "${KEY_ALIAS}" --target-key-id "${KEY_ID}"
fi

# 3. Create KMS-Encrypted Secret in AWS Secrets Manager
if awslocal secretsmanager describe-secret --secret-id "${SECRET_NAME}" >/dev/null 2>&1; then
  echo "--> Secret ${SECRET_NAME} already exists; skipping creation."
else
  echo "--> Creating KMS-encrypted Secret in Secrets Manager..."
  SECRET_PAYLOAD='{
    "DB_USER": "shield_admin",
    "DB_PASSWORD": "P@ssw0rd_KubeShield_2026!",
    "DB_HOST": "postgres.kubeshield.svc.cluster.local",
    "DB_PORT": "5432",
    "DB_NAME": "orders_db"
  }'

  SECRET_ARN=$(awslocal secretsmanager create-secret \
    --name "${SECRET_NAME}" \
    --description "Database credentials encrypted with KMS key" \
    --kms-key-id "${KEY_ID}" \
    --secret-string "${SECRET_PAYLOAD}" \
    --tags Key=Project,Value=KubeShield Key=Environment,Value=LocalStack \
    --query "ARN" --output text)
  echo "    Secret Created: ${SECRET_NAME} (ARN: ${SECRET_ARN})"
fi

# 4. Verification Check (confirms KMS decryption without printing secret values)
echo "--> Verifying Secret retrieval and KMS decryption..."
SECRET_KMS_KEY=$(awslocal secretsmanager describe-secret --secret-id "${SECRET_NAME}" \
  --query "KmsKeyId" --output text)
awslocal secretsmanager get-secret-value --secret-id "${SECRET_NAME}" \
  --query "SecretString" --output text >/dev/null
echo "    Secret is retrievable and encrypted with KMS key: ${SECRET_KMS_KEY}"

echo "================================================================="
echo "==> [LocalStack Init] Successfully initialized KMS and Secrets!"
echo "================================================================="
