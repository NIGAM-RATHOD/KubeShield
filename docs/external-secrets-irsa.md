# Secrets Management Architecture: LocalStack & AWS EKS IRSA

This document covers the **External Secrets Operator (ESO)** integration in **KubeShield**, comparing local development using **LocalStack** (with KMS and Secrets Manager) against enterprise production deployment using **AWS EKS IRSA (IAM Roles for Service Accounts)**.

---

## 1. Architectural Overview

```
[ AWS KMS Customer Managed Key ]
             │ (Envelope Encrypts)
             ▼
[ AWS Secrets Manager ] ◄── "kubeshield/orders-api/db-credentials"
             │
             │ (Decrypted via IAM / STS)
             ▼
[ External Secrets Operator ] ◄── (SecretStore / ExternalSecret)
             │
             │ (Generates in-memory Secret)
             ▼
[ Kubernetes Secret ] ──► "orders-api-db-secret"
             │
             │ (Mounted as envFrom)
             ▼
[ orders-api Pod Container ]
```

---

## 2. LocalStack Local Setup (Development)

In local development, LocalStack runs inside a Docker container mimicking AWS KMS and Secrets Manager on port 4566.

### 2.1 Step 1: Create KMS Customer Managed Key
```bash
aws --endpoint-url=http://localhost:4566 kms create-key \
  --description "KubeShield Orders API Encryption Key" \
  --key-usage "ENCRYPT_DECRYPT" \
  --region us-east-1
```
Output returns `KeyMetadata.KeyId` (e.g., `b2e4b868-0e31-41d9-959c-85153fb08d4b`).

### 2.2 Step 2: Create KMS Alias
```bash
aws --endpoint-url=http://localhost:4566 kms create-alias \
  --alias-name "alias/kubeshield-orders-key" \
  --target-key-id "<KeyId>" \
  --region us-east-1
```

### 2.3 Step 3: Create KMS-Encrypted Secret in Secrets Manager
```bash
aws --endpoint-url=http://localhost:4566 secretsmanager create-secret \
  --name "kubeshield/orders-api/db-credentials" \
  --description "Database credentials encrypted with KMS key" \
  --kms-key-id "alias/kubeshield-orders-key" \
  --secret-string '{"DB_USER":"shield_admin","DB_PASSWORD":"P@ssw0rd_KubeShield_2026!","DB_HOST":"postgres.kubeshield.svc.cluster.local","DB_PORT":"5432","DB_NAME":"orders_db"}' \
  --region us-east-1
```

### 2.4 Step 4: External Secrets Operator Sync
1. `SecretStore` connects to LocalStack:
```yaml
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: localstack-secret-store
  namespace: kubeshield
spec:
  provider:
    aws:
      service: SecretsManager
      region: us-east-1
      endpoint: "http://host.docker.internal:4566"
      auth:
        secretRef:
          accessKeyIDSecretRef:
            name: localstack-credentials
            key: access-key-id
          secretAccessKeySecretRef:
            name: localstack-credentials
            key: secret-access-key
```

2. `ExternalSecret` extracts credentials into `orders-api-db-secret`:
```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: orders-api-db-external-secret
  namespace: kubeshield
spec:
  refreshInterval: "1h"
  secretStoreRef:
    name: localstack-secret-store
    kind: SecretStore
  target:
    name: orders-api-db-secret
    creationPolicy: Owner
  dataFrom:
    - extract:
        key: "kubeshield/orders-api/db-credentials"
```

---

## 3. Enterprise Production: AWS EKS with IRSA

In production AWS EKS clusters, **no static AWS credentials (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`) are ever stored in Kubernetes**. Instead, workloads authenticate using **IAM Roles for Service Accounts (IRSA)**.

### 3.1 Step 1: Enable IAM OIDC Provider on EKS
```bash
eksctl utils associate-iam-oidc-provider \
  --cluster <your-cluster-name> \
  --region us-east-1 \
  --approve
```

### 3.2 Step 2: Create IAM Trust Policy
The trust policy restricts role assumption exclusively to the External Secrets Operator ServiceAccount via Web Identity Federation:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/<OIDC_ID>"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.eks.us-east-1.amazonaws.com/id/<OIDC_ID>:sub": "system:serviceaccount:external-secrets:external-secrets-irsa-sa",
          "oidc.eks.us-east-1.amazonaws.com/id/<OIDC_ID>:aud": "sts.amazonaws.com"
        }
      }
    }
  ]
}
```

### 3.3 Step 3: Create Least-Privilege IAM Policy
The IAM policy grants access solely to the specific secret and KMS decryption key:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSecretsManagerRead",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": "arn:aws:secretsmanager:us-east-1:<ACCOUNT_ID>:secret:kubeshield/orders-api/*"
    },
    {
      "Sid": "AllowKMSDecrypt",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:DescribeKey"
      ],
      "Resource": "arn:aws:kms:us-east-1:<ACCOUNT_ID>:key/<KMS_KEY_ID>"
    }
  ]
}
```

Attach the policy:
```bash
aws iam create-role \
  --role-name KubeShield-ExternalSecrets-Role \
  --assume-role-policy-document file://trust-policy.json

aws iam put-role-policy \
  --role-name KubeShield-ExternalSecrets-Role \
  --policy-name KubeShield-SecretsRead-Policy \
  --policy-document file://iam-policy.json
```

### 3.4 Step 4: Configure Kubernetes ServiceAccount for IRSA
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: external-secrets-irsa-sa
  namespace: external-secrets
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::<ACCOUNT_ID>:role/KubeShield-ExternalSecrets-Role
```

### 3.5 Step 5: Configure Production ClusterSecretStore
In the production manifest, credentials reference the IRSA ServiceAccount JWT token:

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ClusterSecretStore
metadata:
  name: aws-production-irsa-store
spec:
  provider:
    aws:
      service: SecretsManager
      region: us-east-1
      auth:
        jwt:
          serviceAccountRef:
            name: external-secrets-irsa-sa
            namespace: external-secrets
```

---

## 4. Key Security Advantages of the IRSA Pattern

1. **Zero Long-Lived Static Credentials**: AWS temporary STS credentials rotate automatically every hour.
2. **KMS Envelope Encryption**: All credentials in AWS Secrets Manager are encrypted with customer-managed keys (CMK) subject to AWS CloudTrail audit logs.
3. **Cryptographic Identity Attestation**: Only the designated ServiceAccount in the designated namespace can assume the role.
4. **Defense Against Secret Exfiltration**: Pods do not have direct AWS access; they only read the generated native secret in their namespace, while auditors cannot read secrets via RBAC.
