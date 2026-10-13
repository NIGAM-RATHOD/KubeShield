# =============================================================================
# test-network-policies.ps1
# PowerShell verification script for Calico NetworkPolicies in KubeShield
# =============================================================================
$Namespace = "kubeshield"
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "==> Verifying Calico Zero-Trust NetworkPolicies in namespace: $Namespace" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

# Test 1: Frontend -> orders-api (Port 8000) [EXPECTED: 200 OK]
Write-Host "`n[TEST 1] Authorized Traffic: frontend -> orders-api:8000/healthz" -ForegroundColor Yellow
$frontendOutput = kubectl exec -n $Namespace frontend -- curl -s -m 5 -w "`nHTTP_STATUS:%{http_code}" http://orders-api:8000/healthz 2>&1
$statusLine = ($frontendOutput | Select-String "HTTP_STATUS:(\d+)").Matches.Groups[1].Value

if ($statusLine -eq "200") {
    Write-Host "[PASS] TEST 1 SUCCEEDED: Frontend successfully reached orders-api with HTTP 200 OK." -ForegroundColor Green
    Write-Host ($frontendOutput | Where-Object { $_ -notmatch "HTTP_STATUS" })
} else {
    Write-Host "[FAIL] TEST 1 FAILED: Expected HTTP 200, received: $statusLine" -ForegroundColor Red
}

# Test 2: Rogue -> orders-api (Port 8000) [EXPECTED: TIMEOUT / BLOCKED]
Write-Host "`n[TEST 2] Rogue Traffic: rogue -> orders-api:8000/healthz" -ForegroundColor Yellow
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$rogueOutput = kubectl exec -n $Namespace rogue -- curl -v -m 4 http://orders-api:8000/healthz 2>&1
$sw.Stop()

if ($rogueOutput -match "timed out|Connection timed out|exit code 28|failed to connect") {
    Write-Host "[PASS] TEST 2 SUCCEEDED: Rogue pod was BLOCKED by Calico NetworkPolicy! ($([math]::Round($sw.Elapsed.TotalSeconds, 1))s elapsed)" -ForegroundColor Green
    Write-Host "    Packets were silently dropped at the Calico veth filter layer."
} else {
    Write-Host "[FAIL] TEST 2 FAILED: Rogue pod was NOT blocked!" -ForegroundColor Red
    Write-Host $rogueOutput
}

# Test 3: DNS Egress Verification
Write-Host "`n[TEST 3] Testing DNS Egress Resolution" -ForegroundColor Yellow
Write-Host "--> Frontend DNS query:"
kubectl exec -n $Namespace frontend -- nslookup orders-api.kubeshield.svc.cluster.local 2>&1
Write-Host "--> Rogue pod DNS query (should fail/time out):"
kubectl exec -n $Namespace rogue -- nslookup -timeout=3 orders-api.kubeshield.svc.cluster.local 2>&1

Write-Host "`n================================================================================" -ForegroundColor Cyan
Write-Host "==> Calico NetworkPolicy Verification Matrix Summary Completed" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
