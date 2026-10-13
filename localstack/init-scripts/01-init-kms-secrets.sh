#!/usr/bin/env bash
# =============================================================================
# LocalStack Initialization Script
# Runs automatically upon LocalStack startup (mounted at /etc/localstack/init/ready.d)
# Creates a KMS customer managed key and a KMS-encrypted secret in Secrets Manager
# =============================================================================
set -euo pipefail

echo "================================================================="
echo "==> [LocalStack Init] Provisioning KMS Key and Secrets..."
echo "================================================================="

export AWS_DEFAULT_REGION="us-east-1"
export AWS_ACCESS_KEY_ID="test"
export AWS_SECRET_ACCESS_KEY="test"

# 1. Create KMS Customer Managed Key
echo "--> Creating KMS Customer Managed Key (CMK)..."
KMS_OUTPUT=$(awslocal kms create-key \
  --description "KubeShield Orders API Encryption Key" \
  --key-usage "ENCRYPT_DECRYPT" \
  --customer-master-key-spec "SYMMETRIC_DEFAULT" \
  --tags TagKey=Project,TagValue=KubeShield TagKey=Environment,TagValue=LocalStack)

KEY_ID=$(echo "${KMS_OUTPUT}" | jq -r '.KeyMetadata.KeyId')
KEY_ARN=$(echo "${KMS_OUTPUT}" | jq -r '.KeyMetadata.Arn')
echo "    KMS Key Created: ${KEY_ID} (ARN: ${KEY_ARN})"

# 2. Create KMS Alias
echo "--> Creating KMS Alias 'alias/kubeshield-orders-key'..."
awslocal kms create-alias \
  --alias-name "alias/kubeshield-orders-key" \
  --target-key-id "${KEY_ID}"

# 3. Create KMS-Encrypted Secret in AWS Secrets Manager
echo "--> Creating KMS-encrypted Secret in Secrets Manager..."
SECRET_PAYLOAD='{
  "DB_USER": "shield_admin",
  "DB_PASSWORD": "P@ssw0rd_KubeShield_2026!",
  "DB_HOST": "postgres.kubeshield.svc.cluster.local",
  "DB_PORT": "5432",
  "DB_NAME": "orders_db"
}'

SECRET_OUTPUT=$(awslocal secretsmanager create-secret \
  --name "kubeshield/orders-api/db-credentials" \
  --description "Database credentials encrypted with KMS key" \
  --kms-key-id "${KEY_ID}" \
  --secret-string "${SECRET_PAYLOAD}" \
  --tags Key=Project,Value=KubeShield Key=Environment,Value=LocalStack)

SECRET_ARN=$(echo "${SECRET_OUTPUT}" | jq -r '.ARN')
echo "    Secret Created: kubeshield/orders-api/db-credentials (ARN: ${SECRET_ARN})"

# 4. Verification Check
echo "--> Verifying Secret retrieval and KMS decryption..."
RETRIEVED_SECRET=$(awslocal secretsmanager get-secret-value \
  --secret-id "kubeshield/orders-api/db-credentials" \
  --query "SecretString" --output text)

echo "    Decrypted Payload Verified:"
echo "${RETRIEVED_SECRET}" | jq .

echo "================================================================="
echo "==> [LocalStack Init] Successfully initialized KMS and Secrets!"
echo "================================================================="
