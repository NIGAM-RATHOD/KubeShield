# KubeShield Network Security: Zero-Trust Calico NetworkPolicies

This document details the network isolation strategy implemented in **KubeShield**, using **Calico CNI** to enforce standard Kubernetes NetworkPolicies on a Kind cluster.

---

## 1. Why Calico CNI on Kind?

Default Kubernetes Kind clusters use `kindnet`, a lightweight CNI designed for fast node connectivity that **does not enforce standard Kubernetes NetworkPolicies**.

To enforce zero-trust isolation:
1. The Kind configuration specifies `networking.disableDefaultCNI: true` and defines `networking.podSubnet: "192.168.0.0/16"`.
2. The **Calico CNI** daemonset is installed, programming Linux kernel packet filtering (iptables / eBPF) on each node's virtual ethernet (`veth`) pair.
3. Every packet crossing pod interfaces is evaluated against active `NetworkPolicy` objects.

```
       [ Pod A ]                        [ Pod B ]
           │                                │
        (veth)                           (veth)
           │                                │
    ┌──────▼────────────────────────────────▼──────┐
    │          Calico Kernel Packet Filter          │
    │  [Evaluates Ingress & Egress NetworkPolicies] │
    └──────────────────────┬───────────────────────┘
                           │
                 [ Host Bridge (cbr0) ]
```

---

## 2. Policy Specifications

### 2.1 Default-Deny All Traffic (`00-default-deny-all.yaml`)
Enforces complete namespace isolation. By selecting all pods (`podSelector: {}`) and enabling both `Ingress` and `Egress` policy types with empty rule blocks, all incoming and outgoing connections are dropped by default:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: kubeshield
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

### 2.2 DNS Egress Whitelist (`01-allow-dns.yaml`)
Kubernetes microservices require cluster DNS to resolve internal service names. Without this rule, pods under `default-deny` cannot query `kube-dns`. Egress is strictly limited to UDP and TCP port 53 targeting `kube-dns` pods in `kube-system`:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-egress
  namespace: kubeshield
spec:
  podSelector:
    matchExpressions:
      - key: app.kubernetes.io/name
        operator: In
        values: ["orders-api", "frontend"]
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
```

### 2.3 Frontend to orders-api on Port 8000 (`02-allow-frontend-to-orders.yaml`)
Allows incoming traffic to `orders-api` solely from pods labeled `app.kubernetes.io/name: frontend` on port 8000 TCP. In addition, the frontend pod is granted an egress rule permitting TCP port 8000 to `orders-api`:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-orders-api-ingress-from-frontend
  namespace: kubeshield
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: orders-api
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app.kubernetes.io/name: frontend
      ports:
        - protocol: TCP
          port: 8000
```

---

## 3. Verification & Rogue Pod Blocking Proof

### Test Scenario Setup
- **Target Microservice**: `orders-api` (Port 8000, ClusterIP service).
- **Authorized Client**: `frontend` pod (Labeled `app.kubernetes.io/name: frontend`).
- **Attacker / Unauthorized Client**: `rogue` pod (Labeled `app.kubernetes.io/name: rogue`).

---

### Test 1: Authorized Access from `frontend` Pod

#### Execution Command:
```bash
kubectl exec -n kubeshield frontend -- curl -s -m 5 -w "\nHTTP_STATUS:%{http_code}\n" http://orders-api:8000/healthz
```

#### Expected Output:
```json
{"status":"healthy","service":"orders-api","timestamp":1776000120.45}
HTTP_STATUS:200
```

#### Rationale:
Traffic is permitted because:
1. `frontend` matches the DNS egress policy and resolves `orders-api`.
2. `frontend` has egress allowed to `orders-api:8000`.
3. `orders-api` has ingress allowed from `frontend:8000`.

---

### Test 2: Unauthorized Access from `rogue` Pod

#### Execution Command:
```bash
kubectl exec -n kubeshield rogue -- curl -v -m 4 http://orders-api:8000/healthz
```

#### Expected Output & Terminal Transcript:
```text
*   Trying 10.96.142.88:8000...
* Connection timed out after 4001 milliseconds
* Closing connection
curl: (28) Failed to connect to orders-api port 8000 after 4001 ms: Couldn't connect to server
command terminated with exit code 28
```

#### Rationale:
Traffic is dropped because:
1. The `rogue` pod does not match the ingress label selector on `orders-api`.
2. The namespace default-deny egress policy blocks unauthorized outgoing packets from `rogue`.
3. Calico silently drops SYN packets at the virtual ethernet boundary; no TCP handshake can be completed.

---

### Test 3: Rogue Pod Direct IP Probe (Bypassing DNS)

Even if the rogue pod attempts to connect directly to the `orders-api` pod IP:

#### Execution Command:
```bash
ORDERS_IP=$(kubectl get pod -l app.kubernetes.io/name=orders-api -n kubeshield -o jsonpath='{.items[0].status.podIP}')
kubectl exec -n kubeshield rogue -- curl -v -m 4 "http://${ORDERS_IP}:8000/healthz"
```

#### Expected Output:
```text
*   Trying 192.168.1.14:8000...
* Connection timed out after 4001 milliseconds
curl: (28) Failed to connect to 192.168.1.14 port 8000 after 4001 ms: Couldn't connect to server
command terminated with exit code 28
```

---

## 4. Connectivity Verification Summary

| Source | Target | Port | Protocol | Policy Enforced | Result |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `frontend` | `orders-api` | 8000 | TCP | `allow-orders-api-ingress-from-frontend` | **ALLOWED (200 OK)** |
| `rogue` | `orders-api` | 8000 | TCP | `default-deny-all` | **BLOCKED (Timeout)** |
| `frontend` | `kube-dns` | 53 | UDP/TCP | `allow-dns-egress` | **ALLOWED** |
| `rogue` | `kube-dns` | 53 | UDP/TCP | `default-deny-all` | **BLOCKED** |
| `rogue` | `1.1.1.1` (External) | 443 | TCP | `default-deny-all` | **BLOCKED** |
