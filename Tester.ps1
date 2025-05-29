#Requires -Version 5.1

<#
.SYNOPSIS
    Tests the Test-Connection cmdlet for ICMP pings in PowerShell 5.1.
.DESCRIPTION
    This script demonstrates how Test-Connection behaves for ICMP pings
    against reachable, unreachable, and non-existent hosts. It focuses on
    its output object, status codes, latency retrieval, error handling,
    and execution time. This is to gather data for potentially using
    Test-Connection as a replacement for ping.exe or Test-NetConnection
    in other scripts.
.NOTES
    Author: AI Assistant
    Version: 1.0
    Date: 2025-05-19
    Target PowerShell: 5.1
#>

#region --- Configuration ---
Write-Host "--- Test-Connection Specific Test Configuration ---" -ForegroundColor Green

# Host that should be reachable and respond to ICMP pings quickly.
$ReachableHost = "8.8.8.8" # Google's Public DNS

# Host that should NOT respond to ICMP pings (e.g., a non-existent private IP).
# This should result in a timeout.
$UnreachableHostByTimeout = "10.255.255.1"

# Host that might be on the local network but actively refusing pings or firewalled.
# (This is harder to simulate universally, using a known unreachable public IP for now)
# If you have a specific host that gives "Destination Host Unreachable", use it here.
$UnreachableHostByStatus = "192.0.2.1" # TEST-NET-1, reserved for documentation, should be unreachable

# A hostname that should fail DNS resolution.
$NonExistentDnsName = "completely-invalid-hostname-qxyz123.nonexistent"

Write-Host "Reachable Host`: $ReachableHost"
Write-Host "Unreachable Host (Expect Timeout)`: $UnreachableHostByTimeout"
Write-Host "Unreachable Host (Expect Status like DestinationHostUnreachable - may vary)`: $UnreachableHostByStatus"
Write-Host "Non-Existent DNS Name`: $NonExistentDnsName"
Write-Host "-------------------------------------------------" -ForegroundColor Green
#endregion

#region --- Helper Function ---
function Show-TestConnectionDetails {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetHostName,

        [Parameter(Mandatory = $true)]
        [string]$ScenarioDescription
    )

    Write-Host "`n--- Testing '$TargetHostName' --- Scenario`: $ScenarioDescription ---" -ForegroundColor Cyan

    $TestOutput = @{
        TargetHost          = $TargetHostName
        Scenario            = $ScenarioDescription
        ExecutionTimeMs     = $null
        ResultObject        = $null
        ResultStatus        = $null
        ResultLatencyMs     = $null
        ResultAddress       = $null
        ErrorRecord         = $null
        Interpretation      = "Undetermined"
    }

    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        # Using -ErrorAction SilentlyContinue to attempt to get an object even on some failures.
        # Terminating errors (like some DNS issues if not caught by SilentlyContinue) will go to the catch block.
        Write-Host "Executing Test-Connection -ComputerName '$TargetHostName' -Count 1 -ErrorAction SilentlyContinue"
        $PingResult = Test-Connection -ComputerName $TargetHostName -Count 1 -ErrorAction SilentlyContinue
        $Stopwatch.Stop()
        $TestOutput.ExecutionTimeMs = $Stopwatch.ElapsedMilliseconds
        $TestOutput.ResultObject = $PingResult

        if ($null -ne $PingResult) {
            $TestOutput.ResultStatus = $PingResult.Status.ToString()
            $TestOutput.ResultLatencyMs = $PingResult.Latency
            $TestOutput.ResultAddress = if ($null -ne $PingResult.Address) { $PingResult.Address.IPAddressToString } else { "N/A" }

            if ($PingResult.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                $TestOutput.Interpretation = "SUCCESS. Host responded. Latency`: $($PingResult.Latency)ms. Address`: $($TestOutput.ResultAddress)."
                Write-Host $TestOutput.Interpretation -ForegroundColor Green
            } else {
                $TestOutput.Interpretation = "FAILURE (Object Returned). Status`: $($PingResult.Status.ToString()). Latency (if any)`: $($PingResult.Latency)ms."
                Write-Host $TestOutput.Interpretation -ForegroundColor Yellow
            }
        } else {
            # $PingResult is $null. This implies an error occurred that prevented an object from being returned,
            # or -ErrorAction SilentlyContinue suppressed it and $Error[0] might have info.
            $TestOutput.Interpretation = "FAILURE (No Object Returned). Test-Connection did not return a result object."
            if ($Error[0]) {
                $TestOutput.ErrorRecord = $Error[0].Exception.Message
                $TestOutput.Interpretation += " Last PowerShell Error`: $($TestOutput.ErrorRecord)"
                $Error.Clear()
            }
            Write-Warning $TestOutput.Interpretation
        }
    } catch {
        $Stopwatch.Stop()
        $TestOutput.ExecutionTimeMs = $Stopwatch.ElapsedMilliseconds
        $TestOutput.ErrorRecord = $_.Exception.Message
        $TestOutput.Interpretation = "FAILURE (Terminating Error). Exception`: $($TestOutput.ErrorRecord)"
        Write-Error $TestOutput.Interpretation
    }

    Write-Host "`n[Analysis for '$($TestOutput.TargetHost)' - Scenario '$($TestOutput.Scenario)']`:"
    Write-Host "  Execution Time (ms)`: $($TestOutput.ExecutionTimeMs)"
    Write-Host "  Result Object Type (if any)`: $($TestOutput.ResultObject.GetType().FullName)"
    Write-Host "  Result Status`: $($TestOutput.ResultStatus)"
    Write-Host "  Result Latency (ms)`: $($TestOutput.ResultLatencyMs)"
    Write-Host "  Result Responding Address`: $($TestOutput.ResultAddress)"
    Write-Host "  Error Record (if any)`: $($TestOutput.ErrorRecord)"
    Write-Host "  Interpretation`: $($TestOutput.Interpretation)"

    if ($null -ne $TestOutput.ResultObject) {
        Write-Host "`n  [Raw Test-Connection Object Properties for '$($TestOutput.TargetHost)']`:"
        # Display key properties of the PingStatus object
        $TestOutput.ResultObject | Format-List Source, Destination, Address, Latency, Status, BufferSize, Reply | Out-String | Write-Host
        Write-Host "`n  [Get-Member for Test-Connection Object]`:"
        $TestOutput.ResultObject | Get-Member | Out-String | Write-Host
    } else {
        Write-Host "`n  [Raw Test-Connection Object for '$($TestOutput.TargetHost)']`: Not available (`$null)."
    }
    Write-Host "--- End Test for '$TargetHostName' ---" -ForegroundColor Cyan
}
#endregion

#region --- Test Scenarios ---

# Scenario 1: Test a reachable host.
# Expected: Status = Success, Latency > 0, relatively fast execution.
Show-TestConnectionDetails -TargetHostName $ReachableHost -ScenarioDescription "Reachable Host"

# Scenario 2: Test an unreachable host that should time out.
# Expected: Status = TimedOut, relatively slow execution (default timeout of Test-Connection).
Show-TestConnectionDetails -TargetHostName $UnreachableHostByTimeout -ScenarioDescription "Unreachable Host (Expect Timeout)"

# Scenario 3: Test an unreachable host that might return a specific status like "DestinationHostUnreachable".
# (Behavior can depend on network configuration and intermediate routers)
# Expected: Status != Success (e.g., DestinationHostUnreachable, TtlExpired, etc.), execution time might vary.
Show-TestConnectionDetails -TargetHostName $UnreachableHostByStatus -ScenarioDescription "Unreachable Host (Expect Specific Status)"

# Scenario 4: Test a non-existent DNS name.
# Expected: A terminating error (if -ErrorAction Stop) or $PingResult is $null and $Error[0] has info (if -ErrorAction SilentlyContinue).
#           Execution should be relatively fast if DNS fails quickly.
Show-TestConnectionDetails -TargetHostName $NonExistentDnsName -ScenarioDescription "Non-Existent DNS Name"

#endregion

Write-Host "`n--- All Test-Connection Specific Tests Finished ---" -ForegroundColor Green