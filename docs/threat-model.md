# KubeShield Threat Model: STRIDE & MITRE ATT&CK Mapping

This document provides a comprehensive threat model for containerized workloads running on Kubernetes, mapping industry-standard threats to the defense-in-depth controls implemented across **KubeShield**.

---

## 1. Threat Modeling Methodology

The KubeShield security architecture evaluates risks using two complementary security frameworks:
1. **STRIDE**: Identifies attack objectives against system boundaries (*Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege*).
2. **MITRE ATT&CK for Containers & Kubernetes**: Identifies real-world adversary tactics, techniques, and procedures (TTPs) targeting containerized clusters.

```
       [ External Untrusted Network ]
                     │
         ❌ Blocked by Default
                     │
            ┌────────▼────────┐
            │  Ingress/Egress │ ◄── [Calico Default-Deny NetworkPolicy]
            │    Isolation    │
            └────────┬────────┘
                     │
     ┌───────────────┴───────────────┐
     │                               │
┌────▼──────────┐            ┌───────▼────────┐
│  frontend     │            │   rogue-pod    │
│ (Authorized)  │            │ (Unauthorized) │
└────┬──────────┘            └───────┬────────┘
     │ TCP:8000                      │ ❌ Calico Packet Drop
     │ (Explicit Allow)              │    (SYN timeout)
┌────▼───────────────────────────────▼────────┐
│               orders-api Pod                │
│ ┌─────────────────────────────────────────┐ │
│ │  Container: non-root UID 10001          │ │
│ │  readOnlyRootFilesystem: true           │ │
│ │  capabilities: drop: ["ALL"]            │ │
│ │  allowPrivilegeEscalation: false        │ │
│ │  automountServiceAccountToken: false    │ │
│ └─────────────────────────────────────────┘ │
│                     ▲                       │
│                     │ Injected via ESO      │
│ ┌───────────────────┴───────────────────┐   │
│ │   KMS-Encrypted Secret (LocalStack)   │   │
│ └───────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
```

---

## 2. Threat Matrix: Mapping Controls to Risks

| STRIDE Category | MITRE ATT&CK Technique | Threat Description & Attack Vector | Impact | KubeShield Mitigating Control | Verification Mechanism |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Spoofing (Identity)** | **T1556**<br>Modify Authentication Process<br>**T1078**<br>Valid Accounts | An attacker compromises a pod and steals the projected Kubernetes API token (`/var/run/secrets/...`) to impersonate the pod's identity across the cluster. | High: Cluster API abuse, lateral movement, unauthorized querying of cluster metadata. | **1.** `automountServiceAccountToken: false` on default ServiceAccount and custom pods.<br>**2.** Dedicated, unprivileged ServiceAccounts.<br>**3.** Ephemeral IRSA tokens in AWS. | Inspect `/var/run/secrets/kubernetes.io/serviceaccount` in running pod; verify directory does NOT exist. |
| **Tampering (Data/Binary)** | **T1611**<br>Escape to Host<br>**T1543**<br>Create or Modify System Process | A compromised process attempts to overwrite application binaries, install rootkits, download cryptominers, or modify `/etc/passwd`. | Critical: Host or container persistence, rogue binaries execution, supply chain compromise. | **1.** `readOnlyRootFilesystem: true` on container securityContext.<br>**2.** `tmp-volume` mounted via constrained `emptyDir` (sizeLimit 64Mi).<br>**3.** Non-root user (UID 10001). | Run `/api/v1/security-status` probe verifying rootfs write failure (`PermissionError` / `Read-only file system`). |
| **Repudiation (Audit/Logging)** | **T1562**<br>Impair Defenses<br>**T1070**<br>Indicator Removal | Attackers execute malicious activities without leaving trace logs, or tamper with system logs to avoid detection. | Medium: Forensic failure, unmonitored compliance breach. | **1.** Structured JSON logging to stdout (`JSONFormatter`) with request UUIDs, client IPs, timestamps, and UIDs.<br>**2.** Read-only audit role (`auditor-sa`).<br>**3.** CIS Benchmark audit logging. | Inspect pod stdout logs; verify standardized JSON records with non-repudiable transaction IDs. |
| **Information Disclosure** | **T1552**<br>Unsecured Credentials<br>**T1005**<br>Data from Local System | Storing plaintext database passwords in Git repositories, ConfigMaps, or unencrypted Kubernetes Secrets readable by all developers. | Critical: Database exfiltration, credential re-use, unauthorized cloud access. | **1.** Envelope encryption using AWS KMS Customer Managed Keys.<br>**2.** Secrets stored in AWS Secrets Manager / LocalStack.<br>**3.** External Secrets Operator (ESO) syncing at runtime.<br>**4.** Auditor role denied secret read. | Execute `kubectl auth can-i get secrets --as=system:serviceaccount:kubeshield:auditor-sa` -> returns `no`. |
| **Denial of Service (DoS)** | **T1498**<br>Network Denial of Service<br>**T1499**<br>Endpoint DoS | A compromised pod performs port scanning, DNS amplification attacks, or floods internal services across the flat cluster network. | High: Cluster-wide service disruption, resource starvation, external IP blacklisting. | **1.** Calico CNI zero-trust `default-deny-all` ingress and egress.<br>**2.** Explicit egress whitelist restricted only to `kube-dns` on port 53 UDP/TCP.<br>**3.** Ingress whitelist restricted to `frontend` pod on port 8000 TCP. | Execute `curl` from `rogue` pod to `orders-api:8000` -> packet dropped, connection timed out. |
| **Elevation of Privilege** | **T1611**<br>Escape to Host<br>**T1068**<br>Exploitation for Privilege Escalation | A process uses setuid binaries or Linux kernel vulnerabilities (`CAP_SYS_ADMIN`, `CAP_NET_RAW`) to break out of container isolation to the underlying host node. | Critical: Complete cluster node takeover, access to host daemon and etcd. | **1.** Pod Security Admission (PSA) enforced at `restricted` level.<br>**2.** `allowPrivilegeEscalation: false`.<br>**3.** `capabilities: drop: ["ALL"]`.<br>**4.** `seccompProfile: { type: RuntimeDefault }`. | Attempt to run privileged container or `su root` in pod -> admission webhook rejection. |

---

## 3. Defense-in-Depth Implementation Details

### 3.1 Network Isolation Architecture (Calico CNI)
By default, Kubernetes implements a flat network model: any pod can talk to any other pod across any namespace. KubeShield flips this model to **Zero Trust**:
- **Default Deny**: All ingress and egress traffic is dropped by default at the virtual ethernet interface (`veth`) level via iptables/eBPF rules managed by Calico.
- **Micro-segmentation**: Only explicitly permitted traffic flows exist:
  - `frontend -> orders-api:8000/tcp`
  - `orders-api / frontend -> kube-system/kube-dns:53/udp,tcp`

### 3.2 Identity & Access Governance (RBAC)
- **Principle of Least Privilege**:
  - `auditor-sa`: Read-only permissions on workloads and network policies. Explicitly **denied** access to `secrets` and **denied** all write verbs (`create`, `update`, `patch`, `delete`).
  - `deployer-sa`: Scoped strictly to namespace `kubeshield`. Can create and manage deployments and services, but **cannot** modify ClusterRoles, **cannot** touch nodes, and **cannot** deploy to other namespaces.
- **Token Shielding**:
  - In standard Kubernetes, `default` service accounts mount an API token in every pod, giving potential attackers an initial vector. KubeShield disables `automountServiceAccountToken` globally for application workloads.

### 3.3 Secrets Management & Cryptography
- Secrets are never committed to source control or created as raw Kubernetes YAML files.
- Credentials originate in **AWS Secrets Manager** (simulated via LocalStack), encrypted at rest using an **AWS KMS Customer Managed Key**.
- **External Secrets Operator** polls the secret store, decrypts payloads through KMS, and creates ephemeral Kubernetes Secrets in memory for pod consumption.

### 3.4 Runtime Container Hardening
- **Rootless Execution**: Workloads run as UID `10001` (`appuser`). Even if an application has a remote code execution (RCE) flaw, it cannot access kernel interfaces requiring UID 0.
- **Read-Only Root Filesystem**: The root file system is mounted read-only (`readOnlyRootFilesystem: true`). Any attempt by an adversary to drop malicious shell scripts, install utilities, or alter existing files fails immediately.
- **Capability Stripping**: Dropping `ALL` capabilities removes abilities like `CAP_NET_RAW` (packet sniffing), `CAP_DAC_OVERRIDE` (permission bypass), and `CAP_SYS_ADMIN` (container breakouts).
