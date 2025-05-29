#Requires -Version 5.1

<#
.SYNOPSIS
    Educational script to compare Test-Connection, ping.exe, and Test-NetConnection
    for network diagnostics in PowerShell 5.1.
.DESCRIPTION
    This script demonstrates various use cases, object handling, and error trapping
    for Test-Connection, ping.exe, and Test-NetConnection. It aims to highlight
    their differences and strengths for network troubleshooting.
.NOTES
    Author: AI Assistant
    Version: 1.0
    Date: 2023-10-27
#>

#region --- Configuration ---
Write-Host "--- Script Configuration ---" -ForegroundColor Green

# Configure these hosts as needed for your environment.
# ReachableHost should respond to ICMP pings.
$ReachableHost = "8.8.8.8" # Google's Public DNS

# UnreachableHost should NOT respond to ICMP pings (e.g., a non-existent private IP).
$UnreachableHost = "10.255.255.1"

# ReachableHostWithTcpService should be a host with known open TCP ports (e.g., a web server).
$ReachableHostWithTcpService = "google.com"
$CommonTcpPort = 443 # HTTPS, common port likely to be open on web servers
$UnlikelyTcpPort = 12345 # A port that is likely closed

Write-Host "Reachable Host (ICMP)`: $ReachableHost"
Write-Host "Unreachable Host (ICMP)`: $UnreachableHost"
Write-Host "Reachable Host (TCP Service)`: $ReachableHostWithTcpService"
Write-Host "Common TCP Port for Test`: $CommonTcpPort"
Write-Host "Unlikely TCP Port for Test`: $UnlikelyTcpPort"
Write-Host "-----------------------------" -ForegroundColor Green
#endregion

#region --- Helper Function ---
function Show-ObjectDetails {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()] # Allow $null for cases where a command might not return an object on failure
        $ResultObject,

        [Parameter(Mandatory = $true)]
        [string]$ObjectName,

        [Parameter(Mandatory = $false)]
        [string[]]$KeyProperties,

        [Parameter(Mandatory = $false)]
        [string]$AdditionalNotes
    )

    Write-Host "`n--- Details for '$ObjectName' ---" -ForegroundColor Cyan

    Write-Host "`n[1] Raw Output Object(s) for '$ObjectName'`:" -ForegroundColor Yellow
    if ($null -ne $ResultObject) {
        $ResultObject | Format-List * | Out-String | Write-Host
    } else {
        Write-Host "ResultObject is `$null."
    }

    Write-Host "`n[2] Get-Member Output for '$ObjectName'`:" -ForegroundColor Yellow
    if ($null -ne $ResultObject) {
        # Get-Member might act on individual objects if $ResultObject is a collection
        # For simplicity, if it's an array, show Get-Member for the first element if available
        if ($ResultObject -is [array] -and $ResultObject.Count -gt 0) {
            Write-Host "(Showing Get-Member for the first element of the array)"
            $ResultObject[0] | Get-Member | Out-String | Write-Host
        } else {
            $ResultObject | Get-Member | Out-String | Write-Host
        }
    } else {
        Write-Host "ResultObject is `$null, cannot run Get-Member."
    }

    if ($null -ne $KeyProperties -and $KeyProperties.Count -gt 0) {
        Write-Host "`n[3] Accessing Key Properties for '$ObjectName'`:" -ForegroundColor Yellow
        if ($null -ne $ResultObject) {
            foreach ($PropertyPath in $KeyProperties) {
                try {
                    # Handle nested properties like PingReplyDetails.RoundTripTime
                    $Value = $ResultObject | Select-Object -ExpandProperty $PropertyPath -ErrorAction Stop
                    Write-Host "    $($PropertyPath)`: $Value"
                } catch {
                    Write-Host "    $($PropertyPath)`: Error accessing property - $($_.Exception.Message)"
                }
            }
        } else {
            Write-Host "ResultObject is `$null, cannot access key properties."
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($AdditionalNotes)) {
        Write-Host "`n[4] Additional Notes for '$ObjectName'`:" -ForegroundColor Yellow
        Write-Host $AdditionalNotes
    }
    Write-Host "--- End Details for '$ObjectName' ---" -ForegroundColor Cyan
}
#endregion

#region --- Test-Connection (ICMP Ping Focus) ---
Write-Host "`n==================================================" -ForegroundColor Magenta
Write-Host "=== Test-Connection (ICMP Ping Focus) ===" -ForegroundColor Magenta
Write-Host "==================================================" -ForegroundColor Magenta
Write-Host "Test-Connection sends ICMP echo requests (pings) to one or more computers."
Write-Host "It returns rich objects representing the ping results."

# --- Scenario 1: Basic Syntax ---
Write-Host "`n--- Scenario 1: Test-Connection - Basic Syntax ---" -ForegroundColor Yellow
Write-Host "Command`: Test-Connection -ComputerName '$ReachableHost' -Count 1"
$TestConnection_Basic_Result = Test-Connection -ComputerName $ReachableHost -Count 1 -ErrorAction SilentlyContinue
Show-ObjectDetails -ResultObject $TestConnection_Basic_Result -ObjectName "Test-Connection Basic Result" -KeyProperties @("IPV4Address", "StatusCode", "ResponseTime")

# --- Scenario 2: Successful Call ---
Write-Host "`n--- Scenario 2: Test-Connection - Successful Call to '$ReachableHost' ---" -ForegroundColor Yellow
Write-Host "We expect StatusCode 0 for success."
try {
    $TestConnection_Success_Result = Test-Connection -ComputerName $ReachableHost -Count 1 -ErrorAction Stop # Stop to ensure catch block is hit for unexpected errors
    Show-ObjectDetails -ResultObject $TestConnection_Success_Result -ObjectName "Test-Connection Success Result" -KeyProperties @("Address", "IPV4Address", "IPV6Address", "StatusCode", "ResponseTime", "BufferSize", "TimeToLive")
    if ($null -ne $TestConnection_Success_Result -and $TestConnection_Success_Result.StatusCode -eq 0) {
        Write-Host "Interpretation`: Success! IPV4Address is $($TestConnection_Success_Result.IPV4Address), ResponseTime is $($TestConnection_Success_Result.ResponseTime)ms." -ForegroundColor Green
    } else {
        Write-Host "Interpretation`: Call might have 'succeeded' in execution but ping failed. StatusCode`: $($TestConnection_Success_Result.StatusCode)" -ForegroundColor Yellow
    }
} catch {
    Write-Warning "An error occurred during Test-Connection (Successful Call Scenario)`: $($_.Exception.Message)"
    Show-ObjectDetails -ResultObject $null -ObjectName "Test-Connection Success Result (Error)"
}

# --- Scenario 3: Failed Call (Unreachable Host) ---
Write-Host "`n--- Scenario 3: Test-Connection - Failed Call to '$UnreachableHost' ---" -ForegroundColor Yellow
Write-Host "We expect a non-zero StatusCode (e.g., 11010 for Request Timed Out) or an error."
Write-Host "Using -ErrorAction SilentlyContinue to inspect the output object even on failure."
try {
    # -ErrorAction SilentlyContinue allows the command to complete and return an object (if possible)
    # that describes the failure, rather than throwing a terminating script error for common ping failures.
    $TestConnection_Failure_Result = Test-Connection -ComputerName $UnreachableHost -Count 1 -ErrorAction SilentlyContinue
    Show-ObjectDetails -ResultObject $TestConnection_Failure_Result -ObjectName "Test-Connection Failure Result" -KeyProperties @("StatusCode", "Status")
    if ($null -ne $TestConnection_Failure_Result) {
        Write-Host "Interpretation`: Ping failed. StatusCode`: $($TestConnection_Failure_Result.StatusCode) ($($TestConnection_Failure_Result.Status)). This is expected for an unreachable host." -ForegroundColor Yellow
    } elseif ($Error[0]) {
        Write-Warning "Test-Connection to '$UnreachableHost' generated a PowerShell error (e.g., host name resolution failure)`: $($Error[0].Exception.Message)"
        $Error.Clear()
    } else {
        Write-Warning "Test-Connection to '$UnreachableHost' failed, and no specific result object or PowerShell error was captured directly."
    }
} catch {
    # This catch block would typically handle more severe errors not suppressed by SilentlyContinue,
    # or if -ErrorAction Stop was used.
    Write-Warning "A terminating error occurred during Test-Connection (Failed Call Scenario)`: $($_.Exception.Message)"
    Show-ObjectDetails -ResultObject $null -ObjectName "Test-Connection Failure Result (Terminating Error)"
}

# --- Scenario 4: Quiet Mode ---
Write-Host "`n--- Scenario 4: Test-Connection -Quiet Mode ---" -ForegroundColor Yellow
Write-Host "Command`: Test-Connection -ComputerName '$ReachableHost' -Count 1 -Quiet"
$QuietResult_Reachable = Test-Connection -ComputerName $ReachableHost -Count 1 -Quiet
Write-Host "Result for '$ReachableHost' (-Quiet)`: $QuietResult_Reachable (Type`: $($QuietResult_Reachable.GetType().FullName))"
if ($QuietResult_Reachable) { Write-Host "Interpretation`: Host is reachable." -ForegroundColor Green }

Write-Host "`nCommand`: Test-Connection -ComputerName '$UnreachableHost' -Count 1 -Quiet"
$QuietResult_Unreachable = Test-Connection -ComputerName $UnreachableHost -Count 1 -Quiet -ErrorAction SilentlyContinue # Suppress errors for unreachable host
Write-Host "Result for '$UnreachableHost' (-Quiet)`: $QuietResult_Unreachable (Type`: $($QuietResult_Unreachable.GetType().FullName))"
if (-not $QuietResult_Unreachable) { Write-Host "Interpretation`: Host is unreachable." -ForegroundColor Yellow }
Write-Host "Note`: -Quiet returns a simple Boolean. `$true if any ping succeeds, `$false otherwise."
#endregion

#region --- ping.exe (External Command) ---
Write-Host "`n==================================================" -ForegroundColor Magenta
Write-Host "=== ping.exe (External Command) ===" -ForegroundColor Magenta
Write-Host "==================================================" -ForegroundColor Magenta
Write-Host "ping.exe is an external command-line utility. It returns an array of strings."
Write-Host "Error handling relies on parsing output and checking `$LASTEXITCODE."
Write-Host "Note`: Output parsing for ping.exe can be fragile due to localization/language differences."

# --- Scenario 1: Basic Syntax (Successful Call to Reachable Host) ---
Write-Host "`n--- Scenario 1: ping.exe - Successful Call to '$ReachableHost' ---" -ForegroundColor Yellow
Write-Host "Command`: ping.exe -n 1 $ReachableHost"
$PingExe_Success_Output = ping.exe -n 1 $ReachableHost # For PS 5.1, -w timeout is in ms
$PingExe_Success_ExitCode = $LASTEXITCODE

Show-ObjectDetails -ResultObject $PingExe_Success_Output -ObjectName "ping.exe Success Output (String Array)"
Write-Host "Exit Code (`$LASTEXITCODE)`: $PingExe_Success_ExitCode"

if ($PingExe_Success_ExitCode -eq 0) {
    Write-Host "Interpretation`: Exit code 0 suggests success." -ForegroundColor Green
    # Attempt to parse key details (example, may need adjustment for different OS languages)
    foreach ($Line in $PingExe_Success_Output) {
        if ($Line -match "Reply from (.*?):.*?time(?:=|<)([\d\.]+)ms") { # Adjusted regex for 'time=' or 'time<'
            $PingedIP = $Matches[1]
            $ResponseTime = $Matches[2]
            Write-Host "    Parsed IP`: $PingedIP, Parsed Response Time`: ${ResponseTime}ms" -ForegroundColor Green
            break
        }
    }
} else {
    Write-Host "Interpretation`: Exit code $PingExe_Success_ExitCode suggests failure." -ForegroundColor Yellow
}

# --- Scenario 2: Failed Call (Unreachable Host) ---
Write-Host "`n--- Scenario 2: ping.exe - Failed Call to '$UnreachableHost' ---" -ForegroundColor Yellow
Write-Host "Command`: ping.exe -n 1 $UnreachableHost"
$PingExe_Failure_Output = ping.exe -n 1 $UnreachableHost
$PingExe_Failure_ExitCode = $LASTEXITCODE

Show-ObjectDetails -ResultObject $PingExe_Failure_Output -ObjectName "ping.exe Failure Output (String Array)"
Write-Host "Exit Code (`$LASTEXITCODE)`: $PingExe_Failure_ExitCode"

if ($PingExe_Failure_ExitCode -ne 0) {
    Write-Host "Interpretation`: Exit code $PingExe_Failure_ExitCode suggests failure (e.g., 1 for timeout/unreachable)." -ForegroundColor Yellow
    $PingExe_Failure_Output | ForEach-Object { Write-Host "    Output Line`: $_" }
} else {
    # This case should ideally not happen if the host is truly unreachable and ping.exe functions correctly.
    Write-Host "Interpretation`: Exit code 0, but host was expected to be unreachable. Check output." -ForegroundColor Red
    $PingExe_Failure_Output | ForEach-Object { Write-Host "    Output Line`: $_" }
}
Write-Host "Note`: ping.exe errors are generally non-terminating for the script. You must check `$LASTEXITCODE and parse output."
#endregion

#region --- Test-NetConnection (ICMP and TCP) ---
Write-Host "`n==================================================" -ForegroundColor Magenta
Write-Host "=== Test-NetConnection (ICMP and TCP) ===" -ForegroundColor Magenta
Write-Host "==================================================" -ForegroundColor Magenta
Write-Host "Test-NetConnection is versatile. Without -Port, it performs an ICMP ping."
Write-Host "With -Port, it tests TCP connectivity. It returns rich objects."
Write-Host "IMPORTANT for ICMP`: Test-NetConnection in PS 5.1 does NOT have a configurable timeout for ICMP pings."
Write-Host "It uses a system default (often ~4 seconds), unlike Test-Connection or ping.exe -w."

# --- Test-NetConnection: ICMP Ping ---
Write-Host "`n--- Test-NetConnection: ICMP Ping ---" -ForegroundColor Cyan

# --- Scenario 3a: Successful ICMP Call to '$ReachableHost' ---
Write-Host "`n--- Scenario 3a: Test-NetConnection - ICMP Ping - Successful Call to '$ReachableHost' ---" -ForegroundColor Yellow
Write-Host "Command`: Test-NetConnection -ComputerName '$ReachableHost'"
try {
    $TNC_ICMP_Success_Result = Test-NetConnection -ComputerName $ReachableHost -ErrorAction Stop
    Show-ObjectDetails -ResultObject $TNC_ICMP_Success_Result -ObjectName "TNC ICMP Success Result" -KeyProperties @("ComputerName", "RemoteAddress", "PingSucceeded", "PingReplyDetails.StatusCode", "PingReplyDetails.RoundTripTime")
    if ($null -ne $TNC_ICMP_Success_Result -and $TNC_ICMP_Success_Result.PingSucceeded) {
        Write-Host "Interpretation`: ICMP Ping Succeeded. RemoteAddress`: $($TNC_ICMP_Success_Result.RemoteAddress), RoundTripTime`: $($TNC_ICMP_Success_Result.PingReplyDetails.RoundTripTime)ms." -ForegroundColor Green
    } else {
        Write-Host "Interpretation`: ICMP Ping Failed. PingSucceeded`: $($TNC_ICMP_Success_Result.PingSucceeded)" -ForegroundColor Yellow
    }
} catch {
    Write-Warning "An error occurred during Test-NetConnection ICMP (Successful Call Scenario)`: $($_.Exception.Message)"
    Show-ObjectDetails -ResultObject $null -ObjectName "TNC ICMP Success Result (Error)"
}

# --- Scenario 3b: Failed ICMP Call to '$UnreachableHost' ---
Write-Host "`n--- Scenario 3b: Test-NetConnection - ICMP Ping - Failed Call to '$UnreachableHost' ---" -ForegroundColor Yellow
Write-Host "Command`: Test-NetConnection -ComputerName '$UnreachableHost' -ErrorAction SilentlyContinue"
Write-Host "Using -ErrorAction SilentlyContinue to inspect the output object."
try {
    $TNC_ICMP_Failure_Result = Test-NetConnection -ComputerName $UnreachableHost -ErrorAction SilentlyContinue
    Show-ObjectDetails -ResultObject $TNC_ICMP_Failure_Result -ObjectName "TNC ICMP Failure Result" -KeyProperties @("ComputerName", "PingSucceeded", "InterfaceAlias")
    if ($null -ne $TNC_ICMP_Failure_Result -and -not $TNC_ICMP_Failure_Result.PingSucceeded) {
        Write-Host "Interpretation`: ICMP Ping Failed as expected. PingSucceeded`: $($TNC_ICMP_Failure_Result.PingSucceeded)." -ForegroundColor Yellow
        if ($null -ne $TNC_ICMP_Failure_Result.PingReplyDetails) { # PingReplyDetails might be $null on some failures
            Write-Host "    PingReplyDetails.StatusCode`: $($TNC_ICMP_Failure_Result.PingReplyDetails.StatusCode)"
        }
    } elseif ($Error[0]) {
        Write-Warning "Test-NetConnection ICMP to '$UnreachableHost' generated a PowerShell error (e.g., host name resolution failure)`: $($Error[0].Exception.Message)"
        $Error.Clear()
    } else {
        Write-Warning "Test-NetConnection ICMP to '$UnreachableHost' failed, and no specific result object or PowerShell error was captured directly."
    }
} catch {
    Write-Warning "A terminating error occurred during Test-NetConnection ICMP (Failed Call Scenario)`: $($_.Exception.Message)"
    Show-ObjectDetails -ResultObject $null -ObjectName "TNC ICMP Failure Result (Terminating Error)"
}

# --- Test-NetConnection: TCP Port Test ---
Write-Host "`n--- Test-NetConnection: TCP Port Test ---" -ForegroundColor Cyan

# --- Scenario 4a: Successful TCP Port Test to '$ReachableHostWithTcpService:$CommonTcpPort' ---
Write-Host "`n--- Scenario 4a: Test-NetConnection - TCP Port Test - Successful Call to '$ReachableHostWithTcpService`:$CommonTcpPort' ---" -ForegroundColor Yellow
Write-Host "Command`: Test-NetConnection -ComputerName '$ReachableHostWithTcpService' -Port $CommonTcpPort"
try {
    $TNC_TCP_Success_Result = Test-NetConnection -ComputerName $ReachableHostWithTcpService -Port $CommonTcpPort -ErrorAction Stop
    Show-ObjectDetails -ResultObject $TNC_TCP_Success_Result -ObjectName "TNC TCP Success Result" -KeyProperties @("ComputerName", "RemoteAddress", "RemotePort", "TcpTestSucceeded", "PingSucceeded", "PingReplyDetails.RoundTripTime")
    if ($null -ne $TNC_TCP_Success_Result -and $TNC_TCP_Success_Result.TcpTestSucceeded) {
        Write-Host "Interpretation`: TCP Test Succeeded for port $CommonTcpPort. TcpTestSucceeded`: `$true." -ForegroundColor Green
    } else {
        Write-Host "Interpretation`: TCP Test Failed for port $CommonTcpPort. TcpTestSucceeded`: $($TNC_TCP_Success_Result.TcpTestSucceeded)" -ForegroundColor Yellow
    }
} catch {
    Write-Warning "An error occurred during Test-NetConnection TCP (Successful Call Scenario)`: $($_.Exception.Message)"
    Show-ObjectDetails -ResultObject $null -ObjectName "TNC TCP Success Result (Error)"
}

# --- Scenario 4b: Failed TCP Port Test to '$ReachableHostWithTcpService:$UnlikelyTcpPort' (Closed Port) ---
Write-Host "`n--- Scenario 4b: Test-NetConnection - TCP Port Test - Failed Call to '$ReachableHostWithTcpService`:$UnlikelyTcpPort' (Closed Port) ---" -ForegroundColor Yellow
Write-Host "Command`: Test-NetConnection -ComputerName '$ReachableHostWithTcpService' -Port $UnlikelyTcpPort -ErrorAction SilentlyContinue"
try {
    $TNC_TCP_ClosedPort_Result = Test-NetConnection -ComputerName $ReachableHostWithTcpService -Port $UnlikelyTcpPort -ErrorAction SilentlyContinue
    Show-ObjectDetails -ResultObject $TNC_TCP_ClosedPort_Result -ObjectName "TNC TCP Closed Port Result" -KeyProperties @("ComputerName", "RemotePort", "TcpTestSucceeded", "PingSucceeded")
    if ($null -ne $TNC_TCP_ClosedPort_Result -and -not $TNC_TCP_ClosedPort_Result.TcpTestSucceeded) {
        Write-Host "Interpretation`: TCP Test Failed for port $UnlikelyTcpPort as expected (port likely closed). TcpTestSucceeded`: `$false." -ForegroundColor Yellow
    } elseif ($Error[0]) {
        Write-Warning "Test-NetConnection TCP to '$ReachableHostWithTcpService`:$UnlikelyTcpPort' generated a PowerShell error`: $($Error[0].Exception.Message)"
        $Error.Clear()
    } else {
        Write-Warning "Test-NetConnection TCP to '$ReachableHostWithTcpService`:$UnlikelyTcpPort' failed, and no specific result object or PowerShell error was captured directly."
    }
} catch {
    Write-Warning "A terminating error occurred during Test-NetConnection TCP (Closed Port Scenario)`: $($_.Exception.Message)"
    Show-ObjectDetails -ResultObject $null -ObjectName "TNC TCP Closed Port Result (Terminating Error)"
}

# --- Scenario 4c: Failed TCP Port Test to '$UnreachableHost:$CommonTcpPort' (Unreachable Host) ---
Write-Host "`n--- Scenario 4c: Test-NetConnection - TCP Port Test - Failed Call to '$UnreachableHost`:$CommonTcpPort' (Unreachable Host) ---" -ForegroundColor Yellow
Write-Host "Command`: Test-NetConnection -ComputerName '$UnreachableHost' -Port $CommonTcpPort -ErrorAction SilentlyContinue"
try {
    $TNC_TCP_UnreachableHost_Result = Test-NetConnection -ComputerName $UnreachableHost -Port $CommonTcpPort -ErrorAction SilentlyContinue
    Show-ObjectDetails -ResultObject $TNC_TCP_UnreachableHost_Result -ObjectName "TNC TCP Unreachable Host Result" -KeyProperties @("ComputerName", "RemotePort", "TcpTestSucceeded", "PingSucceeded")
    # For an unreachable host, PingSucceeded will be false, and TcpTestSucceeded will also be false.
    if ($null -ne $TNC_TCP_UnreachableHost_Result -and -not $TNC_TCP_UnreachableHost_Result.TcpTestSucceeded -and -not $TNC_TCP_UnreachableHost_Result.PingSucceeded) {
        Write-Host "Interpretation`: TCP Test Failed and Ping Failed for host '$UnreachableHost' as expected. TcpTestSucceeded`: `$false, PingSucceeded`: `$false." -ForegroundColor Yellow
    } elseif ($Error[0]) {
        Write-Warning "Test-NetConnection TCP to '$UnreachableHost`:$CommonTcpPort' generated a PowerShell error`: $($Error[0].Exception.Message)"
        $Error.Clear()
    } else {
        Write-Warning "Test-NetConnection TCP to '$UnreachableHost`:$CommonTcpPort' failed, and no specific result object or PowerShell error was captured directly."
    }
} catch {
    Write-Warning "A terminating error occurred during Test-NetConnection TCP (Unreachable Host Scenario)`: $($_.Exception.Message)"
    Show-ObjectDetails -ResultObject $null -ObjectName "TNC TCP Unreachable Host Result (Terminating Error)"
}
#endregion

#region --- Summary of Key Differences ---
Write-Host "`n==================================================" -ForegroundColor Magenta
Write-Host "=== Summary of Key Differences ===" -ForegroundColor Magenta
Write-Host "==================================================" -ForegroundColor Magenta

Write-Host @"
1. Test-Connection:
   - Primary Use Case: ICMP ping diagnostics.
   - Output: Rich PowerShell objects (`Microsoft.PowerShell.Commands.TestConnectionCommand+PingStatus`) per ping attempt.
   - Object Richness: Detailed information (StatusCode, ResponseTime, IPV4Address, etc.).
   - Error Handling: Returns objects with status codes for ping failures. Can throw terminating errors for more severe issues (e.g., DNS failure) if -ErrorAction Stop is used.
   - Timeout: Configurable with `-TimeoutSeconds` (PSv6+) or relies on default/system behavior for `-Count 1` in PS5.1 (often 1 second per ping, but can vary). `-TimeToLive` is available.
   - Features: `-Quiet` for boolean output, can ping multiple computers.

2. ping.exe:
   - Primary Use Case: Basic ICMP ping diagnostics (external command).
   - Output: Array of strings (console output).
   - Object Richness: None directly. Requires parsing strings.
   - Error Handling: Relies on checking `$LASTEXITCODE` and parsing string output for error messages. Non-terminating for script by default.
   - Timeout: Configurable with `-w <milliseconds>`.
   - Features: Widely available, familiar syntax for many users. Output format can vary by OS language/locale, making parsing less reliable.

3. Test-NetConnection:
   - Primary Use Case: Versatile network diagnostics - ICMP ping (default), TCP port test, route tracing, path MTU discovery.
   - Output: Rich PowerShell objects.
     - ICMP: `Microsoft.PowerShell.Commands.TestNetConnectionResult` (contains PingSucceeded, PingReplyDetails).
     - TCP: `Microsoft.PowerShell.Commands.TestNetConnectionResult` (contains TcpTestSucceeded).
   - Object Richness: Very detailed, context-dependent on the test performed.
   - Error Handling: Returns objects with boolean success flags (PingSucceeded, TcpTestSucceeded). Can throw terminating errors for severe issues if -ErrorAction Stop is used.
   - Timeout (PS 5.1 Specifics):
     - ICMP Ping: **NOT directly configurable.** Uses a system default (often ~4 seconds). This is a key difference from Test-Connection and ping.exe.
     - TCP Test: Timeout is generally not directly specified via a simple parameter in PS 5.1 for the TCP connection attempt itself, but underlying TCP stack timeouts apply.
   - Features: `-Port` for TCP, `-TraceRoute`, `-ConstrainInterface`, `-DiagnoseRouting`. More comprehensive than Test-Connection.

Key Takeaways for PowerShell 5.1:
- For ICMP pings where rich object output is desired:
  - Test-Connection: Good choice, provides detailed objects. Be aware of its default timeout behavior.
  - Test-NetConnection (no -Port): Also good, rich objects. **Crucially, its ICMP timeout is not user-configurable and is typically longer.**
- For ICMP pings where a simple boolean is needed:
  - Test-Connection -Quiet: Efficient.
- For TCP port testing:
  - Test-NetConnection -Port: The standard PowerShell cmdlet.
- If you must use ping.exe:
  - Be prepared for string parsing and checking `$LASTEXITCODE`. Less robust.
- Error Handling:
  - PowerShell cmdlets (Test-Connection, Test-NetConnection) integrate better with try/catch and -ErrorAction.
  - Use -ErrorAction SilentlyContinue with these cmdlets if you want to inspect the returned object even on common failures (like timeouts or port closed) without a script-terminating error.
"@ -ForegroundColor White

Write-Host "`n--- Script Finished ---" -ForegroundColor Green
#endregion
