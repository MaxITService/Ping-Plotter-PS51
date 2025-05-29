#Requires -Version 5.1

<#
.SYNOPSIS
    Investigational script for Test-Connection in PowerShell 5.1.
.DESCRIPTION
    This script focuses on the output and error handling of Test-Connection
    when used with '-Count 1' and '-ErrorAction SilentlyContinue'.
    It aims to provide clear data for populating a result structure like:
    @{ Success = $bool; LatencyMilliseconds = $int_or_null; ErrorMessage = $string_or_null }
    for various network scenarios (reachable, timeout, DNS failure, DNS resolves but host times out).
.NOTES
    Author: AI Assistant
    Version: 2.1
    Date: 2025-05-19
    Target PowerShell: 5.1
#>

#region --- Configuration ---
Write-Host "--- Test-Connection Investigation (test-2.ps1) ---" -ForegroundColor Green

$TestTargets = @(
    @{ Name = "8.8.8.8"; Scenario = "Reachable Host"; ExpectedOutcome = "Success" }
    @{ Name = "10.255.255.1"; Scenario = "Unreachable IP (Expect Timeout)"; ExpectedOutcome = "Failure (Timeout)" }
    @{ Name = "192.0.2.1"; Scenario = "Unreachable IP (TEST-NET-1, Expect Status)"; ExpectedOutcome = "Failure (Specific Status or Timeout)" }
    @{ Name = "non-existent-dns-name-qxyz123.invalid"; Scenario = "Non-Existent DNS Name"; ExpectedOutcome = "Failure (DNS Error, No Object)" }
    @{ Name = "www.sberbank.ru"; Scenario = "DNS Resolves, Host Times Out (e.g., ICMP blocked)"; ExpectedOutcome = "Failure (Timeout, Object Returned)" } # Added this case
)

Write-Host "Test Scenarios Defined:"
$TestTargets | ForEach-Object {
    Write-Host ("  - Target`: {0,-45} Scenario`: {1}" -f $_.Name, $_.Scenario)
}
Write-Host "----------------------------------------------------" -ForegroundColor Green
#endregion

#region --- Helper Function ---
function Get-TestConnectionBehavior {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetHostName,

        [Parameter(Mandatory = $true)]
        [string]$ScenarioDescription
    )

    Write-Host "`n--- Testing Target`: '$TargetHostName' ---" -ForegroundColor Cyan
    Write-Host "Scenario`: $ScenarioDescription"

    $Analysis = @{
        Target                  = $TargetHostName
        Scenario                = $ScenarioDescription
        Timestamp               = Get-Date
        ExecutionTimeMs         = $null
        RawPingResultObject     = $null
        RawErrorRecord          = $null
        # Derived values for the PingPlotter script's $Result hashtable
        DerivedSuccess          = $false
        DerivedLatencyMs        = $null
        DerivedErrorMessage     = "Not yet determined"
        # Detailed components from Test-Connection
        ObjectReturned          = $false
        ObjectStatus            = $null
        ObjectLatency           = $null
        ObjectRespondingAddress = $null
        ObjectDestinationName   = $null # To see if the original name is preserved
        PowerShellErrorMessage  = $null
    }

    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $Error.Clear() # Clear automatic error variable before the call

    try {
        # Key command being tested, matching the PingPlotter script's intended usage
        $PingOperationResult = Test-Connection -ComputerName $TargetHostName -Count 1 -ErrorAction SilentlyContinue
    }
    catch {
        # This catch block would handle truly unexpected, terminating errors from Test-Connection itself,
        # though -ErrorAction SilentlyContinue should prevent most common ping-related issues from terminating.
        $Analysis.PowerShellErrorMessage = "Terminating Exception in Test-Connection call: $($_.Exception.Message)"
        $Analysis.RawErrorRecord = $_
    }
    finally {
        $Stopwatch.Stop()
        $Analysis.ExecutionTimeMs = $Stopwatch.ElapsedMilliseconds
    }

    $Analysis.RawPingResultObject = $PingOperationResult # Store the raw object, if any

    if ($null -ne $PingOperationResult) {
        $Analysis.ObjectReturned = $true
        $Analysis.ObjectStatus = $PingOperationResult.Status.ToString()
        $Analysis.ObjectLatency = $PingOperationResult.Latency
        $Analysis.ObjectDestinationName = $PingOperationResult.Destination # Check what Destination holds

        if ($null -ne $PingOperationResult.Address) {
            $Analysis.ObjectRespondingAddress = $PingOperationResult.Address.IPAddressToString
        } else {
            $Analysis.ObjectRespondingAddress = "N/A"
        }

        if ($PingOperationResult.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
            $Analysis.DerivedSuccess = $true
            $Analysis.DerivedLatencyMs = $PingOperationResult.Latency # Use actual latency on success
            $Analysis.DerivedErrorMessage = $null
        } else {
            $Analysis.DerivedSuccess = $false
            $Analysis.DerivedLatencyMs = $null # Per PingPlotter script logic (set to null on failure)
                                               # $PingOperationResult.Latency would be 0 for TimedOut
            $Analysis.DerivedErrorMessage = "Test-Connection reported failure. Status`: $($PingOperationResult.Status.ToString()). Destination`: $($PingOperationResult.Destination), Resolved Address (if any)`: $($Analysis.ObjectRespondingAddress)."
        }
    } else { # $PingOperationResult is $null
        $Analysis.ObjectReturned = $false
        $Analysis.DerivedSuccess = $false
        $Analysis.DerivedLatencyMs = $null

        if ($Error.Count -gt 0) {
            $Analysis.PowerShellErrorMessage = $Error[0].Exception.Message
            $Analysis.RawErrorRecord = $Error[0]
            $Analysis.DerivedErrorMessage = "Test-Connection returned no object. PowerShell Error`: $($Error[0].Exception.Message)"
        } else {
            $Analysis.PowerShellErrorMessage = "No object returned and no specific PowerShell error in `$Error array."
            $Analysis.DerivedErrorMessage = "Test-Connection returned no object and no specific PowerShell error was captured."
        }
    }

    # --- Outputting Analysis ---
    Write-Host "`n[Raw Data & Object Details for '$TargetHostName']`:"
    Write-Host "  Execution Time (ms)`: $($Analysis.ExecutionTimeMs)"
    Write-Host "  Test-Connection Object Returned?`: $($Analysis.ObjectReturned)"
    if ($Analysis.ObjectReturned) {
        Write-Host "    Object Type`: $($Analysis.RawPingResultObject.GetType().FullName)"
        Write-Host "    Destination Property (original name)`: $($Analysis.ObjectDestinationName)"
        Write-Host "    Status Property`: $($Analysis.ObjectStatus)"
        Write-Host "    Latency Property (raw)`: $($Analysis.ObjectLatency)"
        Write-Host "    Responding Address Property (resolved IP)`: $($Analysis.ObjectRespondingAddress)"
        Write-Host "`n    Raw Object (Format-List)`:"
        $Analysis.RawPingResultObject | Format-List * | Out-String | Write-Host
        Write-Host "`n    Object (Get-Member)`:"
        $Analysis.RawPingResultObject | Get-Member | Out-String | Write-Host
    } else {
        Write-Host "    No Test-Connection object was returned (`$null)."
    }

    if ($null -ne $Analysis.RawErrorRecord) {
        Write-Host "`n  PowerShell Error Record Details`:"
        Write-Host "    Message`: $($Analysis.PowerShellErrorMessage)"
        # Potentially more details from $Analysis.RawErrorRecord if needed
    }

    Write-Host "`n[Derived Values for PingPlotter Script's `$Result Hashtable]`:" -ForegroundColor Yellow
    Write-Host "  \$Result.Success`: $($Analysis.DerivedSuccess)"
    Write-Host "  \$Result.LatencyMilliseconds`: $($Analysis.DerivedLatencyMs)"
    Write-Host "  \$Result.ErrorMessage`: $($Analysis.DerivedErrorMessage)"

    Write-Host "--- End of Test for Target`: '$TargetHostName' ---" -ForegroundColor Cyan
    return $Analysis # Optionally return for further programmatic use
}
#endregion

#region --- Main Test Execution ---
$AllTestResults = foreach ($TargetInfo in $TestTargets) {
    Get-TestConnectionBehavior -TargetHostName $TargetInfo.Name -ScenarioDescription $TargetInfo.Scenario
}

Write-Host "`n`n===================================================="
Write-Host "=== All Investigational Tests Finished ==="
Write-Host "===================================================="

# Optional: Summarize key derived fields from all tests
# Write-Host "`n`n--- Summary of Derived Results ---"
# $AllTestResults | Format-Table Target, Scenario, DerivedSuccess, DerivedLatencyMs, DerivedErrorMessage -AutoSize
#endregion