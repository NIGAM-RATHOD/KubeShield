# KubeShield RBAC Architecture & `kubectl auth can-i` Matrix

This document defines the Role-Based Access Control (RBAC) implementation for **KubeShield**, adhering to the Principle of Least Privilege (PoLP) and CIS Kubernetes Benchmark recommendations.

---

## 1. Identity & ServiceAccount Design

In a hardened cluster, ServiceAccounts must be compartmentalized based on duty:

| ServiceAccount | Namespace | Token Automount | Role / Binding | Intended Use Case |
| :--- | :--- | :--- | :--- | :--- |
| `default` | `kubeshield` | `false` | None | Default namespace SA; token disabled to prevent token projection abuse. |
| `orders-api-sa` | `kubeshield` | `false` | None | Identity for `orders-api` pods; does not communicate with K8s API server. |
| `frontend-sa` | `kubeshield` | `false` | None | Identity for client frontend pod; no K8s API communication needed. |
| `auditor-sa` | `kubeshield` | `false` (explicit mount for scan runner) | `auditor` (Role) | Security audit and compliance inspection service account. |
| `deployer-sa` | `kubeshield` | `false` (explicit mount for CI/CD) | `deployer` (Role) | CI/CD automation runner deploying workloads to `kubeshield`. |

### Automount Token Disabling
By default, Kubernetes mounts an API token at `/var/run/secrets/kubernetes.io/serviceaccount/token`. In KubeShield, this is prevented at both the ServiceAccount and Pod levels:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: default
  namespace: kubeshield
automountServiceAccountToken: false
```

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: orders-api
spec:
  template:
    spec:
      serviceAccountName: orders-api-sa
      automountServiceAccountToken: false
```

---

## 2. Role Definitions

### 2.1 Read-Only Auditor Role (`auditor`)
- **Scope**: Namespace `kubeshield`
- **Permitted Verbs**: `["get", "list", "watch"]`
- **Permitted Resources**: `pods`, `services`, `endpoints`, `configmaps`, `events`, `deployments`, `networkpolicies`, `externalsecrets`
- **Explicit Restrictions**:
  - **NO access to Secrets**: Prevents auditors or audit tools from reading sensitive credentials.
  - **NO write verbs**: Cannot `create`, `update`, `patch`, or `delete` any resource.

### 2.2 Namespace-Scoped Deployer Role (`deployer`)
- **Scope**: Namespace `kubeshield`
- **Permitted Verbs**: `["get", "list", "watch", "create", "update", "patch", "delete"]` on application workloads (`deployments`, `replicasets`, `services`, `configmaps`, `pods`, `networkpolicies`).
- **Permitted Verbs on Secrets**: Read-only (`get`, `list`, `watch`) to verify deployment bindings, but **cannot delete or tamper** with secrets.
- **Explicit Restrictions**:
  - **Cannot manage RBAC**: No permissions on `roles` or `rolebindings` (prevents privilege escalation).
  - **Cannot manage cluster resources**: No permissions on `nodes`, `clusterroles`, `clusterrolebindings`, or namespaces.
  - **Cannot touch other namespaces**: Strictly isolated to `kubeshield`.

---

## 3. `kubectl auth can-i` Verification Matrix

The following test matrix validates that RBAC authorization boundaries are strictly enforced.

| Identity (`--as`) | Verb | Resource | Namespace / Scope | Expected Output | Actual Output | Security Rationale |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `auditor-sa` | `get` | `pods` | `kubeshield` | `yes` | `yes` | Auditor must inspect running pod status and health. |
| `auditor-sa` | `list` | `deployments` | `kubeshield` | `yes` | `yes` | Auditor must inspect deployment configurations. |
| `auditor-sa` | `get` | `networkpolicies`| `kubeshield` | `yes` | `yes` | Auditor must verify firewall and isolation rules. |
| `auditor-sa` | `get` | `secrets` | `kubeshield` | **`no`** | **`no`** | **Critical**: Auditor cannot inspect plaintext secrets or keys. |
| `auditor-sa` | `create` | `pods` | `kubeshield` | **`no`** | **`no`** | Read-only role cannot launch workloads. |
| `auditor-sa` | `delete` | `deployments` | `kubeshield` | **`no`** | **`no`** | Read-only role cannot destroy infrastructure. |
| `auditor-sa` | `get` | `nodes` | Cluster | **`no`** | **`no`** | Scoped strictly to namespace; cannot inspect host nodes. |
| `auditor-sa` | `create` | `roles` | `kubeshield` | **`no`** | **`no`** | Cannot create RBAC rules to escalate privileges. |
| `deployer-sa`| `create` | `deployments` | `kubeshield` | `yes` | `yes` | Deployer must release new application versions. |
| `deployer-sa`| `update` | `deployments` | `kubeshield` | `yes` | `yes` | Deployer must perform rolling updates. |
| `deployer-sa`| `delete` | `pods` | `kubeshield` | `yes` | `yes` | Deployer can evict pods during deployment rollouts. |
| `deployer-sa`| `create` | `services` | `kubeshield` | `yes` | `yes` | Deployer can expose microservice endpoints. |
| `deployer-sa`| `create` | `networkpolicies`| `kubeshield` | `yes` | `yes` | Deployer can configure workload isolation. |
| `deployer-sa`| `get` | `secrets` | `kubeshield` | `yes` | `yes` | Deployer must inspect secret existence for pod references. |
| `deployer-sa`| `delete` | `secrets` | `kubeshield` | **`no`** | **`no`** | Deployer cannot delete synced cryptographic credentials. |
| `deployer-sa`| `create` | `clusterroles` | Cluster | **`no`** | **`no`** | **Critical**: Cannot escalate privileges to cluster-admin. |
| `deployer-sa`| `delete` | `nodes` | Cluster | **`no`** | **`no`** | Cannot disrupt physical/virtual cluster worker nodes. |
| `deployer-sa`| `create` | `deployments` | `default` | **`no`** | **`no`** | Strictly isolated from other namespaces. |

---

## 4. Execution Commands & Terminal Proof

Execute the automated test script:
```bash
./scripts/04-test-rbac.sh
# or on Windows:
powershell -ExecutionPolicy Bypass -File ./scripts/test-rbac.ps1
```

### Terminal Transcript
```text
================================================================================
==> [Phase 3] RBAC Permission Verification Matrix ('kubectl auth can-i')
    Namespace: kubeshield
================================================================================

Running RBAC Can-I Validation Suite...

+---------------+----------+------------------+--------------+----------+---------+
| Identity      | Verb     | Resource         | Scope        | Expected | Result  |
+---------------+----------+------------------+--------------+----------+---------+
| auditor-sa    | get      | pods             | kubeshield   | yes      | yes     |
| auditor-sa    | list     | deployments      | kubeshield   | yes      | yes     |
| auditor-sa    | get      | networkpolicies  | kubeshield   | yes      | yes     |
| auditor-sa    | get      | secrets          | kubeshield   | no       | no      |
| auditor-sa    | create   | pods             | kubeshield   | no       | no      |
| auditor-sa    | delete   | deployments      | kubeshield   | no       | no      |
| auditor-sa    | get      | nodes            | cluster      | no       | no      |
| auditor-sa    | create   | roles            | kubeshield   | no       | no      |
| deployer-sa   | create   | deployments      | kubeshield   | yes      | yes     |
| deployer-sa   | update   | deployments      | kubeshield   | yes      | yes     |
| deployer-sa   | delete   | pods             | kubeshield   | yes      | yes     |
| deployer-sa   | create   | services         | kubeshield   | yes      | yes     |
| deployer-sa   | create   | networkpolicies  | kubeshield   | yes      | yes     |
| deployer-sa   | get      | secrets          | kubeshield   | yes      | yes     |
| deployer-sa   | delete   | secrets          | kubeshield   | no       | no      |
| deployer-sa   | create   | clusterroles     | cluster      | no       | no      |
| deployer-sa   | delete   | nodes            | cluster      | no       | no      |
| deployer-sa   | create   | deployments      | default      | no       | no      |
+---------------+----------+------------------+--------------+----------+---------+

================================================================================
==> RBAC Verification Completed! All security boundary assertions confirmed.
================================================================================
```
