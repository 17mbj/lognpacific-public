<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Michael Bowling Jr
    LinkedIn        : linkedin.com/in/michael-bowling-jr-17mbj/
    GitHub          : github.com/17mbj
    Date Created    : 2026-09-26
    Last Modified   : 2026-09-26
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000500
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-AU-000500/

.TESTED ON
    Date(s) Tested  : 2026-09-26
    Tested By       : Michael Bowling Jr
    Systems Tested  : Microsoft Windows 11 (Azure VM)
    PowerShell Ver. : 5.1

.USAGE
    Run as Administrator on a Windows 11 system:
    PS C:\> .\WN11-AU-000500.ps1
#>

# STIG Remediation: Set Application Event Log Max Size to 32768 KB
# Registry Path: HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application
# Value Name: MaxSize | Value Type: REG_DWORD | Value: 32768 (0x8000)

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"

# Create the registry path if it does not exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the MaxSize value to 32768 KB (32 MB)
Set-ItemProperty -Path $regPath -Name "MaxSize" -Value 32768 -Type DWord

# Verify the setting was applied
$currentValue = (Get-ItemProperty -Path $regPath -Name "MaxSize").MaxSize
if ($currentValue -ge 32768) {
    Write-Host "[PASS] WN11-AU-000500: Application event log MaxSize is set to $currentValue KB." -ForegroundColor Green
} else {
    Write-Host "[FAIL] WN11-AU-000500: Application event log MaxSize is $currentValue KB (expected >= 32768)." -ForegroundColor Red
}

