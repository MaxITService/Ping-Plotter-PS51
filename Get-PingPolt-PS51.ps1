#Requires -Version 5.1

<#
.SYNOPSIS
A PowerShell 5.1+ script that functions as a "ping plotter" analog.
It tests connectivity to a target host, logs results, displays a summary,
and can perform diagnostic actions during outages. Configuration can be
provided via an interactive session or a JSON file.

.DESCRIPTION
This script performs repeated connectivity tests (ICMP or TCP) to a specified target host.
If run without the -ConfigurationFile argument, it prompts the user for all configuration details.
If -ConfigurationFile is used with a path to a JSON configuration file, it uses those settings.

The script defines "Hard Outages" (consecutive failed tests) and optional "Soft Outages"
(consecutive high-latency ICMP pings). When an outage state is entered, configured
diagnostic actions (like logging ipconfig, pinging an alternate host, or running a
custom script) can be performed once per outage period.

Results, including outage periods and diagnostic outputs, are logged to a specified file.
A summary report is displayed at the end of the session. The default log filename includes
a timestamp (yyyyMMdd_HHmmss) if not otherwise specified.
The configuration used for the session can optionally be logged. If logged, it can be
written to the beginning of the main log file, or to a separate specified file (e.g., Config.JSON).

This script is intended for Windows PowerShell 5.1+ environments.

.PARAMETER ConfigurationFile
(Optional) The path to a JSON file containing the script's configuration.
If the path is a simple filename (no path separators), the script will look for it
in its own directory ($PSScriptRoot, or current working directory if $PSScriptRoot is not available).
If this parameter is omitted, the script will run in interactive configuration mode.

.EXAMPLE
.\Get-PingPlot-PS5.ps1
# Runs the script interactively, prompting for all configuration.
# At the end of the interactive session, a JSON representation of the configuration
# will be printed, which can be saved and used with the -ConfigurationFile option.

.EXAMPLE
.\Get-PingPlot-PS5.ps1 -ConfigurationFile "my_ping_config.json"
# Runs the script using settings from 'my_ping_config.json' located in the script's directory.

.EXAMPLE
.\Get-PingPlot-PS5.ps1 -ConfigurationFile "C:\configs\server_monitoring_config.json"
# Runs the script using settings from the specified absolute path.

.NOTES
Date: 2025-05-18
Version: 3.3.2 (PS5.1 Enhanced - Flexible config logging options)

Script Structure:
- Parameter Handling
- Function Definitions:
  - Convert-PSCustomObjectToHashtable (Helper for JSON parsing)
  - Get-YesNoAnswer (Helper for Y/N prompts)
  - Get-IntegerInput (Helper for integer prompts)
  - Get-DiagnosticSettingsFromUser (Helper for diagnostic configuration prompts)
  - Get-PingPlotterConfiguration (Interactive setup or loads from object)
  - Test-PingPlotterConfiguration (Validates the configuration object)
  - Invoke-SingleConnectivityTest (Performs one ICMP or TCP test)
  - Invoke-OutageDiagnosticAction (Runs configured diagnostics)
  - Add-PingPlotterLogEntry (Writes to the log file)
  - Start-PingPlotterSession (Main monitoring loop and outage logic)
  - Show-PingPlotterFinalReport (Displays summary)
- Main Script Logic (Orchestrates the script flow)

Example JSON Configuration File Structure (for PS5.1, use ConvertTo-Json -Depth 5 without -Compress):
<#
{
    "GeneralSettings": {
        "TargetHost": "server.example.com",
        "CheckCount": 1000000,
        "DelaySeconds": 2,
        "PingMode": "ICMP",
        "TargetPort": null,
        "LogFilePath": "ping_plotter_log_20250518_103000.txt",
        "LogConfigurationToJson": false
        // LogConfigurationToJson can be:
        //   false (boolean): Do not log configuration.
        //   true (boolean): Log configuration to the beginning of the main LogFilePath.
        //   "Config.JSON" (string): Log configuration to "Config.JSON" in the script's directory.
        //   "custom/path/to/config_log.json" (string): Log configuration to a custom file path.
    },
    "HardOutageSettings": {
        "ConsecutiveFailuresThreshold": 3,
        "Diagnostics": {
            "Enabled": true,
            "IncludeIpConfig": true,
            "IncludeAlternatePing": true,
            "AlternatePingHost": "8.8.8.8",
            "RunCustomScript": true,
            "CustomScriptPath": "C:\\Scripts\\my_diagnostic_tool.ps1 -Param 'value'"
        }
    },
    "SoftOutageSettings": {
        "Enabled": true,
        "ConsecutiveHighLatencyThreshold": 5,
        "LatencyThresholdMilliseconds": 200,
        "Diagnostics": {
            "Enabled": false,
            "IncludeIpConfig": false,
            "IncludeAlternatePing": false,
            "AlternatePingHost": null,
            "RunCustomScript": false,
            "CustomScriptPath": null
        }
    }
}
#>
#>

#region Script Parameters
param(
    [Parameter(Mandatory = $false, HelpMessage = "Path to the JSON configuration file. If not provided, interactive configuration will start.")]
    [string]$ConfigurationFile
)
#endregion Script Parameters

#region Function Definitions

function Convert-PSCustomObjectToHashtable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        $InputObject
    )
    process {
        if ($null -eq $InputObject) { return $null }

        if ($InputObject -is [array]) {
            $ArrayResult = @()
            foreach ($Item in $InputObject) {
                $ArrayResult += Convert-PSCustomObjectToHashtable -InputObject $Item
            }
            return $ArrayResult
        }

        if ($InputObject -is [System.Management.Automation.PSCustomObject] -or ( $null -ne $InputObject.PSObject -and $InputObject.PSObject.BaseObject -is [System.Management.Automation.PSCustomObject])) {
            $Hashtable = @{}
            foreach ($Property in $InputObject.PSObject.Properties) {
                $Hashtable[$Property.Name] = Convert-PSCustomObjectToHashtable -InputObject $Property.Value
            }
            return $Hashtable
        }
        return $InputObject # Return as-is if not PSCustomObject or array
    }
}

function Get-YesNoAnswer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PromptMessage,
        [Parameter(Mandatory = $true)]
        [bool]$DefaultAnswer
    )
    $YesNoOptions = "[Y/N]"
    $DefaultDisplay = if ($DefaultAnswer) { "Y" } else { "N" }
    do {
        $InputPrompt = Read-Host -Prompt "$PromptMessage $YesNoOptions (Default`: $DefaultDisplay)"
        if ([string]::IsNullOrWhiteSpace($InputPrompt)) { return $DefaultAnswer }
        if ($InputPrompt -eq 'Y' -or $InputPrompt -eq 'y') { return $true }
        if ($InputPrompt -eq 'N' -or $InputPrompt -eq 'n') { return $false }
        Write-Warning "Invalid input. Please enter 'Y' or 'N'."
    } while ($true)
}

function Get-IntegerInput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PromptMessage,
        [Parameter(Mandatory = $true)]
        [int]$DefaultValue,
        $MinValue = $null, 
        $MaxValue = $null, 
        [bool]$AllowEmptyForDefault = $true
    )

    if ($null -eq $MinValue) { $MinValue = [System.Int32]::MinValue }
    if ($null -eq $MaxValue) { $MaxValue = [System.Int32]::MaxValue }

    do {
        $InputPrompt = Read-Host -Prompt "$PromptMessage (Default`: $DefaultValue)"
        if ($AllowEmptyForDefault -and [string]::IsNullOrWhiteSpace($InputPrompt)) {
            Write-Host "Using default value`: $DefaultValue" -ForegroundColor Gray
            return $DefaultValue
        }
        if ($InputPrompt -match '^-?\d+$') { 
            try {
                $IntValue = [int]$InputPrompt
                if ($IntValue -ge $MinValue -and $IntValue -le $MaxValue) {
                    return $IntValue
                } else {
                    Write-Warning "Value must be between $MinValue and $MaxValue."
                }
            } catch {
                Write-Warning "Invalid integer input. Please try again."
            }
        } else {
            Write-Warning "Invalid input. Please enter a valid integer."
        }
    } while ($true)
}

function Get-DiagnosticSettingsFromUser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutageTypeForPrompt, 
        [string]$PromptIndentation = "  "
    )

    $DiagnosticsSettings = @{
        Enabled              = $false
        IncludeIpConfig      = $false
        IncludeAlternatePing = $false
        AlternatePingHost    = $null
        RunCustomScript      = $false
        CustomScriptPath     = $null
    }

    $DiagnosticsSettings.Enabled = Get-YesNoAnswer -PromptMessage ("{0}Enable diagnostic actions for {1}?" -f $PromptIndentation, $OutageTypeForPrompt) -DefaultAnswer $false
    if ($DiagnosticsSettings.Enabled) {
        $DiagnosticsSettings.IncludeIpConfig = Get-YesNoAnswer -PromptMessage ("{0}  Record 'ipconfig /all' output?" -f $PromptIndentation) -DefaultAnswer $false
        $DiagnosticsSettings.IncludeAlternatePing = Get-YesNoAnswer -PromptMessage ("{0}  Ping an alternate host?" -f $PromptIndentation) -DefaultAnswer $false
        if ($DiagnosticsSettings.IncludeAlternatePing) {
            do {
                $DiagnosticsSettings.AlternatePingHost = Read-Host -Prompt ("{0}    Enter alternate host name/IP to ping" -f $PromptIndentation)
                if ([string]::IsNullOrWhiteSpace($DiagnosticsSettings.AlternatePingHost)) {
                    Write-Warning "Alternate ping host cannot be empty if this diagnostic is enabled."
                }
            } while ([string]::IsNullOrWhiteSpace($DiagnosticsSettings.AlternatePingHost))
        }

        $DiagnosticsSettings.RunCustomScript = Get-YesNoAnswer -PromptMessage ("{0}  Run a custom script/command?" -f $PromptIndentation) -DefaultAnswer $false
        if ($DiagnosticsSettings.RunCustomScript) {
            Write-Warning ("{0}    Ensure the custom script/command is a single, valid command line." -f $PromptIndentation)
            Write-Host ("{0}    Note: Standard output and errors from this custom command will be captured and written to the main log file." -f $PromptIndentation) -ForegroundColor Cyan
            do {
                $DiagnosticsSettings.CustomScriptPath = Read-Host -Prompt ("{0}    Enter full custom script path or command line" -f $PromptIndentation)
                if ([string]::IsNullOrWhiteSpace($DiagnosticsSettings.CustomScriptPath)) {
                    Write-Warning "Custom script path/command cannot be empty if this diagnostic is enabled."
                }
            } while ([string]::IsNullOrWhiteSpace($DiagnosticsSettings.CustomScriptPath))
        }
    }
    return $DiagnosticsSettings
}

function Get-PingPlotterConfiguration {
    [CmdletBinding()]
    param ()

    Write-Host "--- Ping Plotter Interactive Configuration ---" -ForegroundColor Yellow
    $Config = @{
        GeneralSettings    = @{}
        HardOutageSettings = @{}
        SoftOutageSettings = @{}
    }

    # General Settings - Basic
    Write-Host "`n-- General Settings --" -ForegroundColor Cyan
    do {
        $Config.GeneralSettings.TargetHost = Read-Host -Prompt "Enter the target host (e.g., server.example.com or IP address)"
        if ([string]::IsNullOrWhiteSpace($Config.GeneralSettings.TargetHost)) {
            Write-Warning "Target host cannot be empty."
        }
    } while ([string]::IsNullOrWhiteSpace($Config.GeneralSettings.TargetHost))

    $Config.GeneralSettings.CheckCount = Get-IntegerInput -PromptMessage "Enter the number of connection checks to perform" -DefaultValue 10000 -MinValue 1
    
    $ConfigureAdvancedSettings = Get-YesNoAnswer -PromptMessage "Configure advanced settings (delay, ping mode, outage rules, diagnostics, config logging)?" -DefaultAnswer $false

    if ($ConfigureAdvancedSettings) {
        $Config.GeneralSettings.DelaySeconds = Get-IntegerInput -PromptMessage "Enter the delay between checks in seconds" -DefaultValue 2 -MinValue 0

        do {
            $ModeInput = Read-Host -Prompt "Select Ping Mode`: [1] ICMP (ping) or [2] TCP (Test-NetConnection) (Default`: 1)"
            if ([string]::IsNullOrWhiteSpace($ModeInput) -or $ModeInput -eq '1') {
                $Config.GeneralSettings.PingMode = 'ICMP'
                Write-Host "Using default mode`: ICMP" -ForegroundColor Gray
                break
            } elseif ($ModeInput -eq '2') {
                $Config.GeneralSettings.PingMode = 'TCP'
                break
            } else {
                Write-Warning "Invalid selection. Please enter '1' or '2'."
            }
        } while ($true)

        if ($Config.GeneralSettings.PingMode -eq 'TCP') {
            $Config.GeneralSettings.TargetPort = Get-IntegerInput -PromptMessage "Enter the target TCP port number for Test-NetConnection" -DefaultValue 443 -MinValue 1 -MaxValue 65535
        } else {
            $Config.GeneralSettings.TargetPort = $null
        }

        $ScriptDirectory = $PSScriptRoot
        if ([string]::IsNullOrWhiteSpace($ScriptDirectory)) { $ScriptDirectory = $PWD.Path }
        $DefaultLogFileNameInteractive = "ping_plotter_log_{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss')
        $DefaultLogPath = Join-Path -Path $ScriptDirectory -ChildPath $DefaultLogFileNameInteractive
        $LogPathInput = Read-Host -Prompt "Enter the full path for the log file (Default`: $DefaultLogPath)"
        $Config.GeneralSettings.LogFilePath = if ([string]::IsNullOrWhiteSpace($LogPathInput)) { $DefaultLogPath } else { $LogPathInput }

        # Hard Outage Settings
        Write-Host "`n-- Hard Outage Settings (Consecutive Failures) --" -ForegroundColor Cyan
        $Config.HardOutageSettings.ConsecutiveFailuresThreshold = Get-IntegerInput -PromptMessage "How many consecutive failed tests trigger a 'Hard Outage'?" -DefaultValue 3 -MinValue 1
        $Config.HardOutageSettings.Diagnostics = Get-DiagnosticSettingsFromUser -OutageTypeForPrompt "Hard Outages" -PromptIndentation "  "

        # Soft Outage Settings (ICMP Only)
        if ($Config.GeneralSettings.PingMode -eq 'ICMP') {
            Write-Host "`n-- Soft Outage Settings (High ICMP Latency) --" -ForegroundColor Cyan
            $Config.SoftOutageSettings.Enabled = Get-YesNoAnswer -PromptMessage "Enable 'Soft Outage' detection based on high ICMP latency?" -DefaultAnswer $false
            if ($Config.SoftOutageSettings.Enabled) {
                $Config.SoftOutageSettings.LatencyThresholdMilliseconds = Get-IntegerInput -PromptMessage "  Enter ICMP latency threshold in milliseconds (e.g., 200)" -DefaultValue 200 -MinValue 1
                $Config.SoftOutageSettings.ConsecutiveHighLatencyThreshold = Get-IntegerInput -PromptMessage "  How many consecutive high-latency pings trigger a 'Soft Outage'?" -DefaultValue 5 -MinValue 1
                $Config.SoftOutageSettings.Diagnostics = Get-DiagnosticSettingsFromUser -OutageTypeForPrompt "Soft Outages (High Latency)" -PromptIndentation "  "
            } else {
                $Config.SoftOutageSettings.LatencyThresholdMilliseconds = $null
                $Config.SoftOutageSettings.ConsecutiveHighLatencyThreshold = $null
                $Config.SoftOutageSettings.Diagnostics = @{ Enabled = $false; IncludeIpConfig = $false; IncludeAlternatePing = $false; AlternatePingHost = $null; RunCustomScript = $false; CustomScriptPath = $null }
            }
        } else { 
            $Config.SoftOutageSettings = @{
                Enabled                             = $false
                LatencyThresholdMilliseconds        = $null
                ConsecutiveHighLatencyThreshold     = $null
                Diagnostics                         = @{ Enabled = $false; IncludeIpConfig = $false; IncludeAlternatePing = $false; AlternatePingHost = $null; RunCustomScript = $false; CustomScriptPath = $null }
            }
        }
        
        # Prompt for logging configuration
        $PromptLogConfigMessage = "`nLog current configuration? [(Y)es to main log|(N)o (default)|(C)onfig.JSON in script dir|(filename/path)]"
        $LogConfigInput = Read-Host -Prompt $PromptLogConfigMessage
        if ([string]::IsNullOrWhiteSpace($LogConfigInput) -or $LogConfigInput -eq 'N' -or $LogConfigInput -eq 'n') {
            $Config.GeneralSettings.LogConfigurationToJson = $false
            Write-Host "Configuration will not be logged." -ForegroundColor Gray
        } elseif ($LogConfigInput -eq 'Y' -or $LogConfigInput -eq 'y') {
            $Config.GeneralSettings.LogConfigurationToJson = $true
            Write-Host "Configuration will be logged to the main log file." -ForegroundColor Gray
        } elseif ($LogConfigInput -eq 'C' -or $LogConfigInput -eq 'c') {
            $Config.GeneralSettings.LogConfigurationToJson = "Config.JSON" 
            Write-Host "Configuration will be logged to 'Config.JSON' in the script directory." -ForegroundColor Gray
        } else {
            $Config.GeneralSettings.LogConfigurationToJson = $LogConfigInput 
            Write-Host "Configuration will be logged to '$LogConfigInput'." -ForegroundColor Gray
        }

    } else {
        Write-Host "`nUsing default values for advanced settings." -ForegroundColor Gray
        $Config.GeneralSettings.DelaySeconds = 2
        $Config.GeneralSettings.PingMode = 'ICMP'
        $Config.GeneralSettings.TargetPort = $null
        
        $ScriptDirectory = $PSScriptRoot
        if ([string]::IsNullOrWhiteSpace($ScriptDirectory)) { $ScriptDirectory = $PWD.Path }
        $DefaultLogFileNameInteractive = "ping_plotter_log_{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss')
        $Config.GeneralSettings.LogFilePath = Join-Path -Path $ScriptDirectory -ChildPath $DefaultLogFileNameInteractive
        Write-Host "Log file will default to`: $($Config.GeneralSettings.LogFilePath)" -ForegroundColor Gray

        $Config.HardOutageSettings.ConsecutiveFailuresThreshold = 3
        $Config.HardOutageSettings.Diagnostics = @{ Enabled = $false; IncludeIpConfig = $false; IncludeAlternatePing = $false; AlternatePingHost = $null; RunCustomScript = $false; CustomScriptPath = $null }

        $Config.SoftOutageSettings = @{
            Enabled                             = $false
            LatencyThresholdMilliseconds        = $null 
            ConsecutiveHighLatencyThreshold     = $null 
            Diagnostics                         = @{ Enabled = $false; IncludeIpConfig = $false; IncludeAlternatePing = $false; AlternatePingHost = $null; RunCustomScript = $false; CustomScriptPath = $null }
        }
        # Default LogConfigurationToJson to false if advanced settings are skipped
        $Config.GeneralSettings.LogConfigurationToJson = $false
    }

    Write-Host "`n--- Interactive Configuration Complete ---" -ForegroundColor Yellow
    Write-Host "You can save the following JSON to a file and use it with the -ConfigurationFile argument for future runs`:" -ForegroundColor Cyan
    Write-Host ($Config | ConvertTo-Json -Depth 5) 
    return $Config
}

function Test-PingPlotterConfiguration {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$ConfigurationData
    )

    $ErrorMessages = New-Object System.Collections.Generic.List[string]

    if (-not $ConfigurationData.ContainsKey('GeneralSettings')) { $ErrorMessages.Add("Missing 'GeneralSettings' section."); Write-Error ($ErrorMessages -join "`n"); return $false }
    $GS = $ConfigurationData.GeneralSettings
    if ([string]::IsNullOrWhiteSpace($GS.TargetHost)) { $ErrorMessages.Add("GeneralSettings.TargetHost cannot be empty.") }
    if ($null -eq $GS.CheckCount -or $GS.CheckCount -isnot [int] -or $GS.CheckCount -le 0) { $ErrorMessages.Add("GeneralSettings.CheckCount must be a positive integer.") }
    if ($null -eq $GS.DelaySeconds -or $GS.DelaySeconds -isnot [int] -or $GS.DelaySeconds -lt 0) { $ErrorMessages.Add("GeneralSettings.DelaySeconds must be a non-negative integer.") }
    if ($GS.PingMode -notin @('ICMP', 'TCP')) { $ErrorMessages.Add("GeneralSettings.PingMode must be 'ICMP' or 'TCP'.") }
    if ($GS.PingMode -eq 'TCP' -and ($null -eq $GS.TargetPort -or $GS.TargetPort -isnot [int] -or $GS.TargetPort -lt 1 -or $GS.TargetPort -gt 65535)) {
        $ErrorMessages.Add("GeneralSettings.TargetPort is required for TCP mode and must be an integer between 1 and 65535.")
    }
    if ([string]::IsNullOrWhiteSpace($GS.LogFilePath)) { $ErrorMessages.Add("GeneralSettings.LogFilePath cannot be empty.") }
    
    if ($GS.ContainsKey('LogConfigurationToJson')) {
        $LogConfigValue = $GS.LogConfigurationToJson
        if ($null -ne $LogConfigValue -and $LogConfigValue -isnot [bool] -and $LogConfigValue -isnot [string]) {
            $ErrorMessages.Add("GeneralSettings.LogConfigurationToJson must be a boolean (true/false) or a string (filepath) if specified.")
        } elseif ($LogConfigValue -is [string] -and [string]::IsNullOrWhiteSpace($LogConfigValue)) {
            $ErrorMessages.Add("GeneralSettings.LogConfigurationToJson, if a string, cannot be empty or consist only of whitespace.")
        }
    }


    if (-not $ConfigurationData.ContainsKey('HardOutageSettings')) { $ErrorMessages.Add("Missing 'HardOutageSettings' section."); Write-Error ($ErrorMessages -join "`n"); return $false }
    $HOS = $ConfigurationData.HardOutageSettings
    if ($null -eq $HOS.ConsecutiveFailuresThreshold -or $HOS.ConsecutiveFailuresThreshold -isnot [int] -or $HOS.ConsecutiveFailuresThreshold -le 0) {
        $ErrorMessages.Add("HardOutageSettings.ConsecutiveFailuresThreshold must be a positive integer.")
    }
    if ($null -eq $HOS.Diagnostics -or $HOS.Diagnostics -isnot [hashtable]) { $ErrorMessages.Add("HardOutageSettings.Diagnostics section is missing or invalid.") }
    elseif ($HOS.Diagnostics.Enabled -eq $true) {
        if ($HOS.Diagnostics.IncludeAlternatePing -eq $true -and [string]::IsNullOrWhiteSpace($HOS.Diagnostics.AlternatePingHost)) {
            $ErrorMessages.Add("HardOutageSettings.Diagnostics.AlternatePingHost cannot be empty if IncludeAlternatePing is true.")
        }
        if ($HOS.Diagnostics.RunCustomScript -eq $true -and [string]::IsNullOrWhiteSpace($HOS.Diagnostics.CustomScriptPath)) {
            $ErrorMessages.Add("HardOutageSettings.Diagnostics.CustomScriptPath cannot be empty if RunCustomScript is true.")
        }
    }

    if (-not $ConfigurationData.ContainsKey('SoftOutageSettings')) { $ErrorMessages.Add("Missing 'SoftOutageSettings' section."); Write-Error ($ErrorMessages -join "`n"); return $false }
    $SOS = $ConfigurationData.SoftOutageSettings
    if ($GS.PingMode -eq 'ICMP' -and $SOS.Enabled -eq $true) {
        if ($null -eq $SOS.LatencyThresholdMilliseconds -or $SOS.LatencyThresholdMilliseconds -isnot [int] -or $SOS.LatencyThresholdMilliseconds -le 0) {
            $ErrorMessages.Add("SoftOutageSettings.LatencyThresholdMilliseconds must be a positive integer if soft outages are enabled.")
        }
        if ($null -eq $SOS.ConsecutiveHighLatencyThreshold -or $SOS.ConsecutiveHighLatencyThreshold -isnot [int] -or $SOS.ConsecutiveHighLatencyThreshold -le 0) {
            $ErrorMessages.Add("SoftOutageSettings.ConsecutiveHighLatencyThreshold must be a positive integer if soft outages are enabled.")
        }
        if ($null -eq $SOS.Diagnostics -or $SOS.Diagnostics -isnot [hashtable]) { $ErrorMessages.Add("SoftOutageSettings.Diagnostics section is missing or invalid.") }
        elseif ($SOS.Diagnostics.Enabled -eq $true) {
            if ($SOS.Diagnostics.IncludeAlternatePing -eq $true -and [string]::IsNullOrWhiteSpace($SOS.Diagnostics.AlternatePingHost)) {
                $ErrorMessages.Add("SoftOutageSettings.Diagnostics.AlternatePingHost cannot be empty if IncludeAlternatePing is true for soft outages.")
            }
            if ($SOS.Diagnostics.RunCustomScript -eq $true -and [string]::IsNullOrWhiteSpace($SOS.Diagnostics.CustomScriptPath)) {
                $ErrorMessages.Add("SoftOutageSettings.Diagnostics.CustomScriptPath cannot be empty if RunCustomScript is true for soft outages.")
            }
        }
    } elseif ($GS.PingMode -eq 'TCP' -and $SOS.Enabled -eq $true) {
        $ErrorMessages.Add("SoftOutageSettings cannot be enabled if GeneralSettings.PingMode is 'TCP'.")
    }

    if ($ErrorMessages.Count -gt 0) {
        Write-Error "Configuration validation failed`:"
        $ErrorMessages | ForEach-Object { Write-Error ("- {0}" -f $_) }
        return $false
    }
    return $true
}

function Invoke-SingleConnectivityTest {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$TargetHostName,
        [Parameter(Mandatory = $true)]
        [ValidateSet('ICMP', 'TCP')]
        [string]$ConnectivityTestMode,
        [Parameter(Mandatory = $false)]
        [int]$OptionalPortNumber
    )

    $Result = @{ Success = $false; LatencyMilliseconds = $null; ErrorMessage = $null; IsHighLatency = $false }

    try {
        if ($ConnectivityTestMode -eq 'ICMP') {
            $PingOutput = ping.exe -n 1 -w 1000 $TargetHostName 2>&1
            $ExitCode = $LASTEXITCODE

            if ($ExitCode -ne 0) {
                $Result.ErrorMessage = "Ping command failed. Exit Code`: $ExitCode. Output`: $($PingOutput -join ' ')"
            } elseif ($PingOutput -match "Reply from .* time(?:=|<)(\d+)ms") {
                $Result.Success = $true
                try {
                    $Result.LatencyMilliseconds = [int]$Matches[1]
                } catch {
                    Write-Warning "Could not parse latency from ping output`: $($Matches[1])"
                    $Result.LatencyMilliseconds = -1 
                }
            } elseif ($PingOutput -match "Request timed out") {
                 $Result.ErrorMessage = "Ping request timed out. Output`: $($PingOutput -join ' ')"
            } else {
                $Result.ErrorMessage = "Ping command returned success code but output was not recognized. Output`: $($PingOutput -join ' ')"
            }
        } elseif ($ConnectivityTestMode -eq 'TCP') {
            if ($null -eq $OptionalPortNumber) {
                throw "Internal Error`: OptionalPortNumber parameter is required for TCP mode in Invoke-SingleConnectivityTest."
            }
            $TncParameters = @{
                ComputerName  = $TargetHostName
                Port          = $OptionalPortNumber
                WarningAction = 'SilentlyContinue'
                ErrorAction   = 'SilentlyContinue'
            }
            $TncResult = Test-NetConnection @TncParameters

            if ($null -ne $TncResult -and $TncResult.TcpTestSucceeded -eq $true) {
                $Result.Success = $true
                if ($null -ne $TncResult.PingReplyDetails -and $null -ne $TncResult.PingReplyDetails.RoundtripTime) {
                    $Result.LatencyMilliseconds = $TncResult.PingReplyDetails.RoundtripTime
                }
            } else {
                $Result.ErrorMessage = "Test-NetConnection failed for host $TargetHostName on port $OptionalPortNumber."
                if ($Error[0]) {
                    $Result.ErrorMessage += " PowerShell Error`: $($Error[0].Exception.Message)"
                    $Error.Clear()
                } elseif ($null -ne $TncResult) {
                     $Result.ErrorMessage += " TNC Status Details`: $($TncResult | Out-String -Width 120)"
                } else {
                    $Result.ErrorMessage += " No specific TNC result object or PowerShell error available."
                }
            }
        }
    } catch {
        $Result.ErrorMessage = "Exception during connectivity test`: $($_.Exception.Message)"
    }
    return $Result
}

function Invoke-OutageDiagnosticAction {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$DiagnosticSettings,
        [Parameter(Mandatory = $true)]
        [string]$LogFilePath,
        [Parameter(Mandatory = $true)]
        [string]$OutageTypeString 
    )

    if (-not $DiagnosticSettings.Enabled) { return }

    Add-PingPlotterLogEntry -MessageToLog "--- Starting Diagnostics for $OutageTypeString ---" -PathToLogFile $LogFilePath

    if ($DiagnosticSettings.IncludeIpConfig) {
        Add-PingPlotterLogEntry -MessageToLog "Diagnostic`: Running ipconfig /all" -PathToLogFile $LogFilePath
        try {
            $IpConfigOutput = ipconfig.exe /all | Out-String
            Add-PingPlotterLogEntry -MessageToLog "ipconfig /all Output`:`n$IpConfigOutput" -PathToLogFile $LogFilePath
        } catch {
            Add-PingPlotterLogEntry -MessageToLog "Error running ipconfig /all`: $($_.Exception.Message)" -PathToLogFile $LogFilePath
        }
    }

    if ($DiagnosticSettings.IncludeAlternatePing -and -not [string]::IsNullOrWhiteSpace($DiagnosticSettings.AlternatePingHost)) {
        Add-PingPlotterLogEntry -MessageToLog "Diagnostic`: Pinging alternate host $($DiagnosticSettings.AlternatePingHost)" -PathToLogFile $LogFilePath
        try {
            $LASTEXITCODE = 0 
            $PingCmd = "ping.exe -n 4 $($DiagnosticSettings.AlternatePingHost)"
            $AlternatePingOutput = Invoke-Expression $PingCmd 2>&1 | Out-String
            $ExitCodeFromPing = $LASTEXITCODE
            $LogEntry = "Alternate Ping Output for $($DiagnosticSettings.AlternatePingHost)`:`n$AlternatePingOutput"
            if ($ExitCodeFromPing -ne 0) {
                $LogEntry += "`nPing Exit Code`: $ExitCodeFromPing"
            }
            Add-PingPlotterLogEntry -MessageToLog $LogEntry -PathToLogFile $LogFilePath
        } catch {
            Add-PingPlotterLogEntry -MessageToLog "Error pinging alternate host $($DiagnosticSettings.AlternatePingHost)`: $($_.Exception.Message)" -PathToLogFile $LogFilePath
        }
    }

    if ($DiagnosticSettings.RunCustomScript -and -not [string]::IsNullOrWhiteSpace($DiagnosticSettings.CustomScriptPath)) {
        Add-PingPlotterLogEntry -MessageToLog "Diagnostic`: Running custom script/command`: $($DiagnosticSettings.CustomScriptPath)" -PathToLogFile $LogFilePath
        try {
            $LASTEXITCODE = 0 
            $CustomScriptOutput = Invoke-Expression "$($DiagnosticSettings.CustomScriptPath) 2>&1" | Out-String
            $ExitCodeFromScript = $LASTEXITCODE
            
            $LogEntryMessage = "Custom Script Output`:`n$CustomScriptOutput"
            if ($ExitCodeFromScript -ne 0) {
                $LogEntryMessage += "`nCustom Script Exit Code`: $ExitCodeFromScript (non-zero suggests an issue or specific status)"
            }
            Add-PingPlotterLogEntry -MessageToLog $LogEntryMessage -PathToLogFile $LogFilePath
        } catch {
            Add-PingPlotterLogEntry -MessageToLog "Error running custom script $($DiagnosticSettings.CustomScriptPath)`: $($_.Exception.Message)" -PathToLogFile $LogFilePath
        }
    }
    Add-PingPlotterLogEntry -MessageToLog "--- Finished Diagnostics for $OutageTypeString ---" -PathToLogFile $LogFilePath
}

function Add-PingPlotterLogEntry {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$MessageToLog,
        [Parameter(Mandatory = $true)]
        [string]$PathToLogFile
    )
    try {
        $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $FormattedMessage = "$Timestamp - $MessageToLog"
        $LogDirectory = Split-Path -Path $PathToLogFile -Parent
        if ($null -ne $LogDirectory -and (-not (Test-Path -Path $LogDirectory -PathType Container))) {
            Write-Verbose "Creating log directory`: $LogDirectory"
            New-Item -Path $LogDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        Add-Content -Path $PathToLogFile -Value $FormattedMessage -ErrorAction Stop
    } catch {
        Write-Warning "Failed to write to log file '$PathToLogFile'`:$($_.Exception.Message)"
    }
}

function Start-PingPlotterSession {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Configuration,
        [Parameter(Mandatory = $true)]
        [string]$EffectiveLogFilePath
    )

    $GS = $Configuration.GeneralSettings
    $HOS = $Configuration.HardOutageSettings
    $SOS = $Configuration.SoftOutageSettings

    $SuccessfulChecks = 0
    $TotalChecksAttemptedThisSession = 0 
    $UnreachabilityLogEvents = New-Object System.Collections.Generic.List[hashtable]

    $ConsecutiveHardFailures = 0
    $IsCurrentlyInHardOutage = $false
    $CurrentHardOutageStartTime = $null

    $ConsecutiveSoftFailures = 0
    $IsCurrentlyInSoftOutage = $false
    $CurrentSoftOutageStartTime = $null

    $ModeDetails = if ($GS.TargetPort) { "`:$($GS.TargetPort)" } else { '' }
    $InitialLogMessage = "--- Session started for host`: $($GS.TargetHost) --- Checks`: $($GS.CheckCount), Delay`: $($GS.DelaySeconds)s, Mode`: $($GS.PingMode)$ModeDetails --- "
    Add-PingPlotterLogEntry -MessageToLog $InitialLogMessage -PathToLogFile $EffectiveLogFilePath
    if ($GS.PingMode -eq 'ICMP' -and $SOS.Enabled) {
        Add-PingPlotterLogEntry -MessageToLog "Soft Outage Detection Enabled`: Latency > $($SOS.LatencyThresholdMilliseconds)ms for $($SOS.ConsecutiveHighLatencyThreshold) consecutive checks." -PathToLogFile $EffectiveLogFilePath
    }

    Write-Host "Starting connectivity check session... Press Ctrl+C to interrupt." -ForegroundColor Green

    for ($i = 1; $i -le $GS.CheckCount; $i++) {
        try {
            $TotalChecksAttemptedThisSession = $i
            $CompletedChecksCount = $i - 1
            
            $CoreProgressText = "Checking $($GS.TargetHost) ($i/$($GS.CheckCount))... Success`: $SuccessfulChecks/$CompletedChecksCount"

            $OutageEventsCount = $UnreachabilityLogEvents.Count
            $DisplayOutageCount = $OutageEventsCount
            $LastOutageTimeForDisplay = $null
            $OutageTypeDescriptionForDisplay = ""

            if ($IsCurrentlyInHardOutage) {
                $DisplayOutageCount++
                $LastOutageTimeForDisplay = $CurrentHardOutageStartTime
                $OutageTypeDescriptionForDisplay = "current hard outage started at"
            } elseif ($IsCurrentlyInSoftOutage) {
                $DisplayOutageCount++
                $LastOutageTimeForDisplay = $CurrentSoftOutageStartTime
                $OutageTypeDescriptionForDisplay = "current soft outage started at"
            } elseif ($OutageEventsCount -gt 0) {
                $LastOutageTimeForDisplay = $UnreachabilityLogEvents[$OutageEventsCount - 1].StartTime
                $OutageTypeDescriptionForDisplay = "last outage started at"
            }

            $OutageInfoString = ""
            if ($DisplayOutageCount -eq 0) {
                $OutageInfoString = "[No outages detected]"
            } else {
                $OutageNoun = if ($DisplayOutageCount -eq 1) { "outage" } else { "outages" }
                $LastOutageTimeString = if ($LastOutageTimeForDisplay) { $LastOutageTimeForDisplay.ToString('yyyy-MM-dd HH:mm:ss') } else { "N/A" }
                $OutageInfoString = "[$DisplayOutageCount $OutageNoun detected, $OutageTypeDescriptionForDisplay $LastOutageTimeString]"
            }
            
            $BaseOutputForProgressLine = "$CoreProgressText $OutageInfoString"
            $StatusSpecificOutput = ""
            $StatusSpecificColor = $null

            $TestResult = Invoke-SingleConnectivityTest -TargetHostName $GS.TargetHost -ConnectivityTestMode $GS.PingMode -OptionalPortNumber $GS.TargetPort

            if ($TestResult.Success) {
                $SuccessfulChecks++
                $ConsecutiveHardFailures = 0 

                if ($IsCurrentlyInHardOutage) {
                    $IsCurrentlyInHardOutage = $false
                    $UnreachableEndTime = Get-Date
                    $UnreachabilityLogEvents.Add(@{ Host = $GS.TargetHost; StartTime = $CurrentHardOutageStartTime; EndTime = $UnreachableEndTime; Type = "Hard" })
                    $LogMsg = "Host $($GS.TargetHost) became reachable. Hard Outage ended. Was unreachable from $($CurrentHardOutageStartTime.ToString('yyyy-MM-dd HH:mm:ss')) to $($UnreachableEndTime.ToString('yyyy-MM-dd HH:mm:ss'))."
                    Add-PingPlotterLogEntry -MessageToLog $LogMsg -PathToLogFile $EffectiveLogFilePath
                    $CurrentHardOutageStartTime = $null
                }

                if ($GS.PingMode -eq 'ICMP' -and $SOS.Enabled) {
                    if ($TestResult.LatencyMilliseconds -gt $SOS.LatencyThresholdMilliseconds) {
                        $TestResult.IsHighLatency = $true 
                        $ConsecutiveSoftFailures++
                        $StatusSpecificOutput = " (High Latency`: $($TestResult.LatencyMilliseconds)ms)"
                        $StatusSpecificColor = 'Yellow'
                        if ($ConsecutiveSoftFailures -ge $SOS.ConsecutiveHighLatencyThreshold -and -not $IsCurrentlyInSoftOutage) {
                            $IsCurrentlyInSoftOutage = $true
                            $CurrentSoftOutageStartTime = Get-Date
                            $LogMsg = "Host $($GS.TargetHost) entered Soft Outage (High Latency). Latency`: $($TestResult.LatencyMilliseconds)ms. Threshold`: >$($SOS.LatencyThresholdMilliseconds)ms for $($SOS.ConsecutiveHighLatencyThreshold) checks."
                            Add-PingPlotterLogEntry -MessageToLog $LogMsg -PathToLogFile $EffectiveLogFilePath
                            Invoke-OutageDiagnosticAction -DiagnosticSettings $SOS.Diagnostics -LogFilePath $EffectiveLogFilePath -OutageTypeString "Soft Outage (High Latency)"
                        }
                    } else { 
                        $ConsecutiveSoftFailures = 0
                        if ($IsCurrentlyInSoftOutage) {
                            $IsCurrentlyInSoftOutage = $false
                            $SoftOutageEndTime = Get-Date
                            $UnreachabilityLogEvents.Add(@{ Host = $GS.TargetHost; StartTime = $CurrentSoftOutageStartTime; EndTime = $SoftOutageEndTime; Type = "Soft (High Latency)" })
                            $LogMsg = "Host $($GS.TargetHost) exited Soft Outage (High Latency). Latency`: $($TestResult.LatencyMilliseconds)ms. Was in soft outage from $($CurrentSoftOutageStartTime.ToString('yyyy-MM-dd HH:mm:ss')) to $($SoftOutageEndTime.ToString('yyyy-MM-dd HH:mm:ss'))."
                            Add-PingPlotterLogEntry -MessageToLog $LogMsg -PathToLogFile $EffectiveLogFilePath
                            $CurrentSoftOutageStartTime = $null
                        }
                    }
                }
            } else { 
                $ConsecutiveHardFailures++
                $ConsecutiveSoftFailures = 0 
                $StatusSpecificOutput = " (Failed)"
                $StatusSpecificColor = 'Red'

                if ($IsCurrentlyInSoftOutage) {
                    $IsCurrentlyInSoftOutage = $false
                    $SoftOutageEndTime = Get-Date 
                    $UnreachabilityLogEvents.Add(@{ Host = $GS.TargetHost; StartTime = $CurrentSoftOutageStartTime; EndTime = $SoftOutageEndTime; Type = "Soft (High Latency) - Ended by Failure" })
                    $LogMsg = "Host $($GS.TargetHost) exited Soft Outage due to connection failure. Was in soft outage from $($CurrentSoftOutageStartTime.ToString('yyyy-MM-dd HH:mm:ss')) to $($SoftOutageEndTime.ToString('yyyy-MM-dd HH:mm:ss'))."
                    Add-PingPlotterLogEntry -MessageToLog $LogMsg -PathToLogFile $EffectiveLogFilePath
                    $CurrentSoftOutageStartTime = $null
                }

                if ($ConsecutiveHardFailures -ge $HOS.ConsecutiveFailuresThreshold -and -not $IsCurrentlyInHardOutage) {
                    $IsCurrentlyInHardOutage = $true
                    $CurrentHardOutageStartTime = Get-Date
                    $LogMsg = "Host $($GS.TargetHost) became unreachable (Hard Outage). Error`: $($TestResult.ErrorMessage)"
                    Add-PingPlotterLogEntry -MessageToLog $LogMsg -PathToLogFile $EffectiveLogFilePath
                    Invoke-OutageDiagnosticAction -DiagnosticSettings $HOS.Diagnostics -LogFilePath $EffectiveLogFilePath -OutageTypeString "Hard Outage"
                }
            }
            
            Write-Host -NoNewline "`r"
            Write-Host -NoNewline $BaseOutputForProgressLine
            if (-not [string]::IsNullOrEmpty($StatusSpecificOutput)) {
                Write-Host -NoNewline $StatusSpecificOutput -ForegroundColor $StatusSpecificColor
            }
            $CurrentLineLength = $BaseOutputForProgressLine.Length + $StatusSpecificOutput.Length
            if ($CurrentLineLength -lt ([System.Console]::WindowWidth - 1) ) {
                Write-Host -NoNewline (" " * ([System.Console]::WindowWidth - 1 - $CurrentLineLength))
            }

            if ($i -lt $GS.CheckCount) { Start-Sleep -Seconds $GS.DelaySeconds }

        } catch { 
            Write-Warning "`nUnexpected error or interruption during check loop (Check $i of $($GS.CheckCount))`:$($_.Exception.Message)"
            Add-PingPlotterLogEntry -MessageToLog "Session interrupted or error after $TotalChecksAttemptedThisSession checks`: $($_.Exception.Message)" -PathToLogFile $EffectiveLogFilePath
            throw 
        }
    }
    Write-Host "" 

    if ($IsCurrentlyInHardOutage) {
        $UnreachableEndTime = Get-Date
        $UnreachabilityLogEvents.Add(@{ Host = $GS.TargetHost; StartTime = $CurrentHardOutageStartTime; EndTime = $UnreachableEndTime; Type = "Hard"; StillUnreachable = $true })
        $LogMsg = "Host $($GS.TargetHost) was still unreachable (Hard Outage) at session end. Unreachable since $($CurrentHardOutageStartTime.ToString('yyyy-MM-dd HH:mm:ss'))."
        Add-PingPlotterLogEntry -MessageToLog $LogMsg -PathToLogFile $EffectiveLogFilePath
    }
    if ($IsCurrentlyInSoftOutage) {
        $SoftOutageEndTime = Get-Date
        $UnreachabilityLogEvents.Add(@{ Host = $GS.TargetHost; StartTime = $CurrentSoftOutageStartTime; EndTime = $SoftOutageEndTime; Type = "Soft (High Latency)"; StillUnreachable = $true })
        $LogMsg = "Host $($GS.TargetHost) was still in Soft Outage (High Latency) at session end. Soft outage since $($CurrentSoftOutageStartTime.ToString('yyyy-MM-dd HH:mm:ss'))."
        Add-PingPlotterLogEntry -MessageToLog $LogMsg -PathToLogFile $EffectiveLogFilePath
    }

    Add-PingPlotterLogEntry -MessageToLog "Session for host '$($GS.TargetHost)' completed. Total checks performed`: $TotalChecksAttemptedThisSession out of $($GS.CheckCount) configured." -PathToLogFile $EffectiveLogFilePath

    return @{
        TotalChecks          = $TotalChecksAttemptedThisSession
        SuccessfulChecks     = $SuccessfulChecks
        UnreachabilityEvents = $UnreachabilityLogEvents
        TargetHost           = $GS.TargetHost
    }
}

function Show-PingPlotterFinalReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$SessionResults
    )

    Write-Host "`n--- Session Report for $($SessionResults.TargetHost) ---" -ForegroundColor Cyan

    Write-Host "Outage Log Summary`:" -ForegroundColor Yellow
    if ($null -ne $SessionResults.UnreachabilityEvents -and $SessionResults.UnreachabilityEvents.Count -gt 0) {
        foreach ($Event in $SessionResults.UnreachabilityEvents) {
            $StartTimeStr = $Event.StartTime.ToString('yyyy-MM-dd HH:mm:ss')
            $EndTimeStr = $Event.EndTime.ToString('yyyy-MM-dd HH:mm:ss')
            $TypeStr = $Event.Type
            if ($Event.StillUnreachable) {
                Write-Output "Host $($Event.Host) was in a '$TypeStr' state from $StartTimeStr and was still in this state at session end ($EndTimeStr)."
            } else {
                Write-Output "Host $($Event.Host) experienced a '$TypeStr' state from $StartTimeStr to $EndTimeStr."
            }
        }
    } else {
        Write-Output "No periods of unreachability or high latency (if configured) recorded."
    }

    $TotalChecks = $SessionResults.TotalChecks
    $SuccessfulChecks = $SessionResults.SuccessfulChecks
    $SuccessRate = if ($null -ne $TotalChecks -and $TotalChecks -gt 0) { ($SuccessfulChecks / $TotalChecks) * 100 } else { 0 }

    Write-Host "`nSummary`:" -ForegroundColor Yellow
    Write-Output "Target Host`: $($SessionResults.TargetHost)"
    Write-Output "Total Checks Performed`: $TotalChecks"
    Write-Output "Successful Checks`: $SuccessfulChecks"
    Write-Output "Success Rate`: $($SuccessRate.ToString('F2'))%"
    Write-Host "-----------------------------------------" -ForegroundColor Cyan
}

#endregion Function Definitions

#region Main Script Logic

$UserConfiguration = $null
$ConfigurationSource = ""
$EffectiveLogFilePath = $null
$ScriptBaseDirectory = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ScriptBaseDirectory)) { $ScriptBaseDirectory = $PWD.Path }


try {
    Write-Output "Welcome to PowerShell Ping Plotter Analog (PS5.1 Windows Edition)!"

    if ($PSBoundParameters.ContainsKey('ConfigurationFile') -and -not [string]::IsNullOrWhiteSpace($ConfigurationFile)) {
        $ProvidedPath = $ConfigurationFile
        Write-Verbose "Parameter '-ConfigurationFile' provided with value`: '$ProvidedPath'"

        $ResolvedPath = $null
        if ($ProvidedPath -match "[\\/]") { 
            $ResolvedPath = Resolve-Path -Path $ProvidedPath -ErrorAction SilentlyContinue
        } else { 
            $ResolvedPath = Join-Path -Path $ScriptBaseDirectory -ChildPath $ProvidedPath
        }

        if ($null -eq $ResolvedPath -or -not (Test-Path -Path $ResolvedPath -PathType Leaf)) {
            throw "Configuration file specified via -ConfigurationFile ('$ProvidedPath') not found or is not a file. Attempted to resolve to`: '$($ResolvedPath | Out-String -NoNewline)'."
        }
        $EffectiveConfigurationFilePathForMessage = $ResolvedPath.ToString() 
        Write-Output "Loading configuration from JSON file`: '$EffectiveConfigurationFilePathForMessage'"
        
        $JsonContent = Get-Content -Path $ResolvedPath -Raw -ErrorAction Stop
        $ParsedJson = $JsonContent | ConvertFrom-Json -ErrorAction Stop
        
        if ($null -eq $ParsedJson) {
            throw "Failed to parse JSON content from '$($ResolvedPath.ToString())', or the file is empty."
        }
        if ($ParsedJson -is [array]) {
            throw "The configuration file '$($ResolvedPath.ToString())' contains a JSON array at its root. A single JSON object is expected for configuration."
        }
        
        $UserConfiguration = Convert-PSCustomObjectToHashtable -InputObject $ParsedJson
        if ($null -eq $UserConfiguration) {
             throw "Failed to convert the parsed JSON object from '$($ResolvedPath.ToString())' into a usable hashtable configuration."
        }
        $ConfigurationSource = "JSON File`: $EffectiveConfigurationFilePathForMessage"
    } else {
        Write-Host "`nNo configuration file specified. Starting interactive configuration..." -ForegroundColor Cyan
        $UserConfiguration = Get-PingPlotterConfiguration 
        $ConfigurationSource = "Interactive"
    }

    Write-Verbose "Validating final configuration from '$ConfigurationSource'."
    if (-not (Test-PingPlotterConfiguration -ConfigurationData $UserConfiguration)) {
        throw "Configuration is invalid. Please correct the errors listed above or in the JSON file and try again."
    }
    
    $ConfiguredLogPath = $null
    if ($UserConfiguration.GeneralSettings.ContainsKey('LogFilePath')) {
        $ConfiguredLogPath = $UserConfiguration.GeneralSettings.LogFilePath
    }

    if (-not [string]::IsNullOrWhiteSpace($ConfiguredLogPath)) {
        $EffectiveLogFilePath = $ConfiguredLogPath
        if (-not (Split-Path -Path $EffectiveLogFilePath -IsAbsolute)) {
            $EffectiveLogFilePath = Join-Path -Path $ScriptBaseDirectory -ChildPath $EffectiveLogFilePath
            Write-Verbose "Relative log file path from configuration resolved to`: $EffectiveLogFilePath"
        }
    } else { 
        $DefaultLogFileNameMain = "ping_plotter_log_{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss')
        $EffectiveLogFilePath = Join-Path -Path $ScriptBaseDirectory -ChildPath $DefaultLogFileNameMain
        Write-Verbose "Log file path not specified or empty in configuration, defaulting to`: $EffectiveLogFilePath"
    }
    $UserConfiguration.GeneralSettings.LogFilePath = $EffectiveLogFilePath 
    Write-Output "Operational logs will be saved to`: $EffectiveLogFilePath"


    $LogConfigSetting = $null
    if ($UserConfiguration.GeneralSettings.ContainsKey('LogConfigurationToJson')) {
        $LogConfigSetting = $UserConfiguration.GeneralSettings.LogConfigurationToJson
    }

    $PathForConfigLog = $null
    $ShouldLogConfig = $false

    if ($LogConfigSetting -is [bool] -and $LogConfigSetting -eq $true) { # Y option from interactive, or 'true' from JSON
        $PathForConfigLog = $EffectiveLogFilePath # Main operational log file
        $ShouldLogConfig = $true
        Write-Verbose "Configuration will be logged to the main operational log file: $PathForConfigLog"
    } elseif ($LogConfigSetting -is [string]) {
        if ($LogConfigSetting -eq "Config.JSON") { # C option from interactive, or "Config.JSON" from JSON
            $PathForConfigLog = Join-Path -Path $ScriptBaseDirectory -ChildPath "Config.JSON"
            $ShouldLogConfig = $true
            Write-Verbose "Configuration will be logged to a separate file in script directory: $PathForConfigLog"
        } elseif (-not [string]::IsNullOrWhiteSpace($LogConfigSetting)) { # Custom filename/path option
            $CustomPath = $LogConfigSetting
            if (-not (Split-Path -Path $CustomPath -IsAbsolute)) {
                $PathForConfigLog = Join-Path -Path $ScriptBaseDirectory -ChildPath $CustomPath
                Write-Verbose "Relative custom path for config log resolved to: $PathForConfigLog"
            } else {
                $PathForConfigLog = $CustomPath
                Write-Verbose "Absolute custom path for config log: $PathForConfigLog"
            }
            $ShouldLogConfig = $true
        }
    } # If $LogConfigSetting is $false (boolean) or $null (not specified), $ShouldLogConfig remains $false.

    if ($ShouldLogConfig -and -not [string]::IsNullOrWhiteSpace($PathForConfigLog)) {
        Write-Verbose "Attempting to write configuration JSON to: $PathForConfigLog"
        try {
            $ConfigJsonForLog = $UserConfiguration | ConvertTo-Json -Depth 5
            $LogHeader = "--- BEGIN CONFIGURATION JSON (as of session start $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) ---"
            $LogFooter = "--- END CONFIGURATION JSON ---"
            $FullConfigLogMessage = "$LogHeader`n$ConfigJsonForLog`n$LogFooter`n" 
            
            $LogDirectory = Split-Path -Path $PathForConfigLog -Parent
            if ($null -ne $LogDirectory -and (-not (Test-Path -Path $LogDirectory -PathType Container))) {
                Write-Verbose "Creating directory for config log: $LogDirectory"
                New-Item -Path $LogDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }
            
            if ($PathForConfigLog -eq $EffectiveLogFilePath) { 
                # Prepend to the main operational log file
                Add-Content -Path $PathForConfigLog -Value $FullConfigLogMessage -ErrorAction Stop
            } else { 
                # Create or overwrite a separate file for the configuration
                Set-Content -Path $PathForConfigLog -Value $FullConfigLogMessage -ErrorAction Stop
            }
            Write-Output "Configuration JSON has been written to '$PathForConfigLog'."
        } catch {
            Write-Warning "Failed to write configuration JSON to log file '$PathForConfigLog': $($_.Exception.Message)"
        }
    } elseif (($LogConfigSetting -is [bool] -and $LogConfigSetting -eq $false) -or ($null -eq $LogConfigSetting)) {
        Write-Verbose "Logging of configuration JSON is disabled or not specified."
    }


    $GS = $UserConfiguration.GeneralSettings
    $ModeDisplay = if ($GS.TargetPort) { "`:$($GS.TargetPort)" } else { '' }
    Write-Output "`nStarting Ping Plotter session for host`: $($GS.TargetHost)"
    Write-Output "Configuration`: Checks`: $($GS.CheckCount), Delay`: $($GS.DelaySeconds)s, Mode`: $($GS.PingMode)$ModeDisplay"

    $SessionOutcome = Start-PingPlotterSession -Configuration $UserConfiguration -EffectiveLogFilePath $EffectiveLogFilePath

    if ($null -ne $SessionOutcome) {
        Show-PingPlotterFinalReport -SessionResults $SessionOutcome
        Write-Output "`nSession complete. Detailed operational logs are in '$EffectiveLogFilePath'."
    } else {
        Write-Warning "Session did not complete as expected or was interrupted before results could be compiled. Reporting may be incomplete."
        Write-Output "Check the operational log file for details`: '$EffectiveLogFilePath'."
    }

} catch {
    Write-Error "An unexpected error or interruption occurred in the main script execution:"
    Write-Error ("Message`: {0}" -f $_.Exception.Message)
    if ($_.InvocationInfo) {
        Write-Error ("Script`: {0}, Line`: {1}" -f ($_.InvocationInfo.ScriptName | Out-String -Stream).Trim(), ($_.InvocationInfo.ScriptLineNumber | Out-String -Stream).Trim())
    }
    if ($_.ScriptStackTrace) {
        Write-Warning "Stack Trace`: $($_.ScriptStackTrace)"
    }
    
    if ($null -ne $EffectiveLogFilePath) {
        try {
            Add-PingPlotterLogEntry -MessageToLog "CRITICAL ERROR: Script execution halted. Error Message: $($_.Exception.Message)" -PathToLogFile $EffectiveLogFilePath
        } catch {
            Write-Warning "CRITICAL ERROR: Additionally, failed to write error details to log file '$EffectiveLogFilePath'."
        }
    }
    Write-Error "Script execution halted."
    exit 1
} finally {
    Write-Verbose "Script execution finished."
}

#endregion Main Script Logic

