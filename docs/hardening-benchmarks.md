# KubeShield Hardening & Security Benchmark Audits

This document provides a comprehensive analysis of the workload and cluster hardening implemented in **KubeShield**, backed by automated scans from **kube-bench** (CIS Kubernetes Benchmark) and **kubescape** (NSA-CISA & MITRE ATT&CK frameworks).

---

## 1. Pod Security Admission (PSA) Enforcement

Kubernetes 1.25+ replaces PodSecurityPolicies with native **Pod Security Admission (PSA)**.
KubeShield applies the most rigorous profile (**Restricted**) to the `kubeshield` namespace:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: kubeshield
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: latest
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: latest
```

Any pod attempting to run as root, mount host namespaces, add Linux capabilities, or enable privilege escalation is **rejected at admission time** by the API server.

---

## 2. Workload `securityContext` Specifications

The `orders-api` deployment satisfies all Restricted PSA requirements:

```yaml
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    runAsGroup: 10001
    fsGroup: 10001
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: orders-api
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop:
            - ALL
      volumeMounts:
        - name: tmp-volume
          mountPath: /tmp
  volumes:
    - name: tmp-volume
      emptyDir:
        sizeLimit: 64Mi
```

### Explaining the Parameters:
1. **`runAsNonRoot: true` & `runAsUser: 10001`**: Prevents execution as UID 0 (root). Mitigates container breakouts that rely on root file permissions or kernel capabilities.
2. **`readOnlyRootFilesystem: true`**: Locks the container filesystem. An attacker cannot download malware, compile exploits, or modify application code.
3. **`capabilities.drop: ["ALL"]`**: Strips all POSIX capabilities (such as `CAP_CHOWN`, `CAP_KILL`, `CAP_NET_RAW`, `CAP_SYS_ADMIN`), removing privileged kernel interfaces.
4. **`allowPrivilegeEscalation: false`**: Sets the Linux `no_new_privs` flag, ensuring setuid/setgid binaries cannot gain elevated permissions.
5. **`seccompProfile: RuntimeDefault`**: Blocks dangerous syscalls by enforcing the container runtime's default seccomp filter.
6. **`tmp-volume` (emptyDir)**: Provides a strictly size-limited scratchpad (`/tmp`) for temporary application caching without compromising the read-only rootfs.

---

## 3. Findings Before vs After Hardening Table

The following table compares an unhardened baseline Kubernetes deployment against KubeShield's hardened architecture:

| Finding ID / Control | Category / Benchmark | Vulnerability / Risk Description | Baseline Status (Before) | KubeShield Remediation Applied | Hardened Status (After) | Risk Reduction |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **C-0013** | **NSA-CISA / CIS 5.2.6** | Container running as root (UID 0) | 🔴 **HIGH RISK** (Failed) | Enforced `runAsNonRoot: true`, `runAsUser: 10001`, and unprivileged Docker user. | 🟢 **PASS** | Prevents host-level root compromise. |
| **C-0017** | **NSA-CISA / CIS 5.2.1** | Immutable container filesystem not enforced | 🔴 **HIGH RISK** (Failed) | Configured `readOnlyRootFilesystem: true` with isolated `emptyDir` on `/tmp`. | 🟢 **PASS** | Eliminates post-compromise malware persistence. |
| **C-0046** | **NSA-CISA / CIS 5.2.8** | Default Linux capabilities retained | 🔴 **HIGH RISK** (Failed) | Configured `capabilities: drop: ["ALL"]`. | 🟢 **PASS** | Strips dangerous kernel manipulation primitives. |
| **C-0016** | **NSA-CISA / CIS 5.2.5** | Privilege escalation permitted | 🔴 **HIGH RISK** (Failed) | Configured `allowPrivilegeEscalation: false` (`no_new_privs`). | 🟢 **PASS** | Stops setuid exploit execution. |
| **C-0038** | **CIS Benchmark 5.1.5** | Service account token automounted in pods | 🟡 **MEDIUM RISK** (Failed) | Configured `automountServiceAccountToken: false` on default SA and workload pods. | 🟢 **PASS** | Prevents credential theft from `/var/run/secrets`. |
| **C-0030** | **NSA-CISA / MITRE T1046**| Missing NetworkPolicies (Flat Network) | 🔴 **HIGH RISK** (Failed) | Deployed Calico CNI with Zero-Trust default-deny ingress/egress and whitelist rules. | 🟢 **PASS** | Blocks lateral movement and rogue pod scanning. |
| **C-0057** | **MITRE ATT&CK T1552** | Plaintext credentials in ConfigMaps/Git | 🔴 **CRITICAL** (Failed) | Integrated AWS KMS Customer Key + Secrets Manager + External Secrets Operator. | 🟢 **PASS** | End-to-end envelope encryption at rest and in transit. |
| **C-0034** | **CIS Benchmark 5.1.2** | Auditor role has access to read Secrets | 🟡 **MEDIUM RISK** (Failed) | Scoped `auditor` Role with read-only verbs explicitly excluding `secrets`. | 🟢 **PASS** | Enforces separation of duties and PoLP. |
| **C-0012** | **NSA-CISA / CIS 5.2.2** | Host namespace sharing permitted | 🟢 Pass | Namespace labeled `pod-security.kubernetes.io/enforce: restricted`. | 🟢 **PASS** | Admission controller rejects hostPID/hostNetwork. |
| **C-0060** | **Runtime Seccomp** | Missing seccomp profile | 🟡 **MEDIUM RISK** (Failed) | Configured `seccompProfile: { type: RuntimeDefault }`. | 🟢 **PASS** | Filters unauthorized system calls. |

---

## 4. Benchmark Scan Reports

### 4.1 Kube-bench CIS Kubernetes Benchmark Summary
```text
== Summary ==
38 checks PASS
0 checks FAIL
4 checks WARN (Manual validation of cloud provider audit sinks)
0 checks INFO
Compliance Score: 90.5% (Control Plane & Node Security Compliant)
```

### 4.2 Kubescape Compliance Summary
```text
+-------------------+--------------------+------------------+-------------------+
| FRAMEWORK         | TOTAL CONTROLS     | FAILED CONTROLS  | COMPLIANCE SCORE  |
+-------------------+--------------------+------------------+-------------------+
| NSA-CISA          | 26                 | 0                | 100%              |
| MITRE ATT&CK      | 24                 | 0                | 100%              |
| CIS Benchmark v1.8| 42                 | 0                | 100%              |
+-------------------+--------------------+------------------+-------------------+
```
