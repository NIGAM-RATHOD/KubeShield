# =============================================================================
# test-rbac.ps1
# PowerShell verification script for 'kubectl auth can-i' permission matrix
# =============================================================================
$Namespace = "kubeshield"
$AuditorSA = "system:serviceaccount:${Namespace}:auditor-sa"
$DeployerSA = "system:serviceaccount:${Namespace}:deployer-sa"

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "==> RBAC Permission Matrix Verification ('kubectl auth can-i')" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

$Tests = @(
    # Auditor SA
    @{ SA = "auditor-sa"; FullSA = $AuditorSA; Verb = "get"; Resource = "pods"; Scope = $Namespace; Expected = "yes" },
    @{ SA = "auditor-sa"; FullSA = $AuditorSA; Verb = "list"; Resource = "deployments"; Scope = $Namespace; Expected = "yes" },
    @{ SA = "auditor-sa"; FullSA = $AuditorSA; Verb = "get"; Resource = "networkpolicies"; Scope = $Namespace; Expected = "yes" },
    @{ SA = "auditor-sa"; FullSA = $AuditorSA; Verb = "get"; Resource = "secrets"; Scope = $Namespace; Expected = "no" },
    @{ SA = "auditor-sa"; FullSA = $AuditorSA; Verb = "create"; Resource = "pods"; Scope = $Namespace; Expected = "no" },
    @{ SA = "auditor-sa"; FullSA = $AuditorSA; Verb = "delete"; Resource = "deployments"; Scope = $Namespace; Expected = "no" },
    @{ SA = "auditor-sa"; FullSA = $AuditorSA; Verb = "get"; Resource = "nodes"; Scope = ""; Expected = "no" },
    @{ SA = "auditor-sa"; FullSA = $AuditorSA; Verb = "create"; Resource = "roles"; Scope = $Namespace; Expected = "no" },

    # Deployer SA
    @{ SA = "deployer-sa"; FullSA = $DeployerSA; Verb = "create"; Resource = "deployments"; Scope = $Namespace; Expected = "yes" },
    @{ SA = "deployer-sa"; FullSA = $DeployerSA; Verb = "update"; Resource = "deployments"; Scope = $Namespace; Expected = "yes" },
    @{ SA = "deployer-sa"; FullSA = $DeployerSA; Verb = "delete"; Resource = "pods"; Scope = $Namespace; Expected = "yes" },
    @{ SA = "deployer-sa"; FullSA = $DeployerSA; Verb = "create"; Resource = "services"; Scope = $Namespace; Expected = "yes" },
    @{ SA = "deployer-sa"; FullSA = $DeployerSA; Verb = "create"; Resource = "networkpolicies"; Scope = $Namespace; Expected = "yes" },
    @{ SA = "deployer-sa"; FullSA = $DeployerSA; Verb = "get"; Resource = "secrets"; Scope = $Namespace; Expected = "yes" },
    @{ SA = "deployer-sa"; FullSA = $DeployerSA; Verb = "delete"; Resource = "secrets"; Scope = $Namespace; Expected = "no" },
    @{ SA = "deployer-sa"; FullSA = $DeployerSA; Verb = "create"; Resource = "clusterroles"; Scope = ""; Expected = "no" },
    @{ SA = "deployer-sa"; FullSA = $DeployerSA; Verb = "delete"; Resource = "nodes"; Scope = ""; Expected = "no" },
    @{ SA = "deployer-sa"; FullSA = $DeployerSA; Verb = "create"; Resource = "deployments"; Scope = "default"; Expected = "no" }
)

Write-Host "`nIdentity      | Verb     | Resource         | Scope        | Expected | Result"
Write-Host "--------------+----------+------------------+--------------+----------+-------"

$Failures = 0
foreach ($t in $Tests) {
    $kubectlArgs = @("auth", "can-i", $t.Verb, $t.Resource, "--as=$($t.FullSA)")
    if ($t.Scope -ne "") {
        $kubectlArgs += @("-n", $t.Scope)
    }
    $actual = ((& kubectl @kubectlArgs 2>$null) | Out-String).Trim()
    $scopeDisplay = if ($t.Scope -ne "") { $t.Scope } else { "cluster" }

    if ($actual -eq $t.Expected) {
        $color = "Green"
    } else {
        $color = "Red"
        $Failures++
    }
    Write-Host ("{0,-13} | {1,-8} | {2,-16} | {3,-12} | {4,-8} | " -f $t.SA, $t.Verb, $t.Resource, $scopeDisplay, $t.Expected) -NoNewline
    Write-Host ("{0,-6}" -f $actual) -ForegroundColor $color
}

if ($Failures -gt 0) {
    Write-Host "`nRBAC Verification FAILED: $Failures assertion(s) did not match expectations." -ForegroundColor Red
    exit 1
}
Write-Host "`nRBAC Verification Complete. All assertions passed." -ForegroundColor Green
