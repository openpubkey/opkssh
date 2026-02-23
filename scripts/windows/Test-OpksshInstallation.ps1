#Requires -Version 5.1

<#
.SYNOPSIS
    Tests the opkssh installation on Windows Server.

.DESCRIPTION
    This script validates that opkssh has been correctly installed and configured
    on a Windows Server. It performs various checks to ensure all components are
    in place and properly configured.

.PARAMETER Verbose
    Show detailed information about each test.

.EXAMPLE
    .\Test-OpksshInstallation.ps1

.EXAMPLE
    .\Test-OpksshInstallation.ps1 -Verbose

.NOTES
    This script can be run by any user (does not require Administrator privileges).
#>

[CmdletBinding()]
param()

# Test results tracking
$script:PassedTests = 0
$script:FailedTests = 0
$script:WarningTests = 0
$script:TotalTests = 0

function Write-TestResult {
    <#
    .SYNOPSIS
        Writes a formatted test result.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$TestName,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet('Pass', 'Fail', 'Warning', 'Info')]
        [string]$Result,
        
        [Parameter()]
        [string]$Message = ""
    )
    
    $script:TotalTests++
    
    $symbol = switch ($Result) {
        'Pass'    { "PASS"; $script:PassedTests++; $color = 'Green' }
        'Fail'    { "FAIL"; $script:FailedTests++; $color = 'Red' }
        'Warning' { "WARN"; $script:WarningTests++; $color = 'Yellow' }
        'Info'    { "INFO"; $color = 'Cyan' }
    }
    
    $resultText = "[$symbol] $TestName"
    Write-Host $resultText -ForegroundColor $color
    
    if ($Message) {
        Write-Host "    $Message" -ForegroundColor Gray
    }
}

function Test-BinaryInstallation {
    <#
    .SYNOPSIS
        Tests if opkssh binary is installed.
    #>
    param()
    
    Write-Host "`nBinary Installation:" -ForegroundColor Cyan
    
    # Test 1: Binary exists
    $binaryPath = "C:\Program Files\opkssh\opkssh.exe"
    if (Test-Path $binaryPath) {
        Write-TestResult -TestName "Binary exists" -Result Pass -Message $binaryPath
        
        # Test 2: Binary is executable
        try {
            $version = & $binaryPath --version 2>&1
            Write-TestResult -TestName "Binary is executable" -Result Pass -Message "Version: $version"
        } catch {
            Write-TestResult -TestName "Binary is executable" -Result Fail -Message $_.Exception.Message
        }
        
        # Test 3: Binary size check
        $fileSize = (Get-Item $binaryPath).Length
        if ($fileSize -gt 1MB) {
            Write-TestResult -TestName "Binary size reasonable" -Result Pass -Message "$([math]::Round($fileSize/1MB, 2)) MB"
        } else {
            Write-TestResult -TestName "Binary size reasonable" -Result Warning -Message "File seems small: $([math]::Round($fileSize/1KB, 2)) KB"
        }
        
    } else {
        Write-TestResult -TestName "Binary exists" -Result Fail -Message "Not found at $binaryPath"
        Write-TestResult -TestName "Binary is executable" -Result Fail -Message "Skipped (binary not found)"
        Write-TestResult -TestName "Binary size reasonable" -Result Fail -Message "Skipped (binary not found)"
    }
    
    # Test 4: Binary in PATH
    $pathDirs = $env:Path -split ';'
    if ($pathDirs -contains "C:\Program Files\opkssh") {
        Write-TestResult -TestName "Binary in system PATH" -Result Pass
    } else {
        Write-TestResult -TestName "Binary in system PATH" -Result Warning -Message "Not in PATH (you may need to restart your shell)"
    }
}

function Test-ConfigurationFiles {
    <#
    .SYNOPSIS
        Tests if configuration files and directories exist.
    #>
    param()
    
    Write-Host "`nConfiguration Files:" -ForegroundColor Cyan
    
    $configBase = "C:\ProgramData\opk"
    
    # Test 1: Config directory exists
    if (Test-Path $configBase) {
        Write-TestResult -TestName "Config directory exists" -Result Pass -Message $configBase
    } else {
        Write-TestResult -TestName "Config directory exists" -Result Fail -Message "Not found at $configBase"
        return
    }
    
    # Test 2: Required files
    $requiredFiles = @{
        'auth_id'   = Join-Path $configBase "auth_id"
        'providers' = Join-Path $configBase "providers"
        'config.yml' = Join-Path $configBase "config.yml"
    }
    
    foreach ($file in $requiredFiles.GetEnumerator()) {
        if (Test-Path $file.Value) {
            Write-TestResult -TestName "$($file.Key) file exists" -Result Pass
        } else {
            Write-TestResult -TestName "$($file.Key) file exists" -Result Fail -Message "Not found at $($file.Value)"
        }
    }
    
    # Test 3: Required directories
    $requiredDirs = @{
        'policy.d' = Join-Path $configBase "policy.d"
        'logs'     = Join-Path $configBase "logs"
    }
    
    foreach ($dir in $requiredDirs.GetEnumerator()) {
        if (Test-Path $dir.Value) {
            Write-TestResult -TestName "$($dir.Key) directory exists" -Result Pass
        } else {
            Write-TestResult -TestName "$($dir.Key) directory exists" -Result Warning -Message "Not found at $($dir.Value)"
        }
    }
    
    # Test 4: Providers file content
    $providersPath = Join-Path $configBase "providers"
    if (Test-Path $providersPath) {
        $providersContent = Get-Content $providersPath -Raw
        if ($providersContent -match 'accounts.google.com|login.microsoftonline.com') {
            Write-TestResult -TestName "Providers file has content" -Result Pass
        } else {
            Write-TestResult -TestName "Providers file has content" -Result Warning -Message "File exists but may be empty"
        }
    }
}

function Test-SshdConfiguration {
    <#
    .SYNOPSIS
        Tests OpenSSH Server configuration.
    #>
    param()
    
    Write-Host "`nOpenSSH Server Configuration:" -ForegroundColor Cyan
    
    # Test 1: sshd service exists
    $sshdService = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if ($sshdService) {
        Write-TestResult -TestName "sshd service exists" -Result Pass
        
        # Test 2: sshd service is running
        if ($sshdService.Status -eq 'Running') {
            Write-TestResult -TestName "sshd service is running" -Result Pass
        } else {
            Write-TestResult -TestName "sshd service is running" -Result Warning -Message "Service is $($sshdService.Status)"
        }
        
        # Test 3: sshd service startup type
        if ($sshdService.StartType -eq 'Automatic') {
            Write-TestResult -TestName "sshd starts automatically" -Result Pass
        } else {
            Write-TestResult -TestName "sshd starts automatically" -Result Warning -Message "StartType is $($sshdService.StartType)"
        }
    } else {
        Write-TestResult -TestName "sshd service exists" -Result Fail -Message "Service not found"
        Write-TestResult -TestName "sshd service is running" -Result Fail -Message "Skipped (service not found)"
        Write-TestResult -TestName "sshd starts automatically" -Result Fail -Message "Skipped (service not found)"
    }
    
    # Test 4: sshd_config exists
    $sshdConfigPath = "C:\ProgramData\ssh\sshd_config"
    if (Test-Path $sshdConfigPath) {
        Write-TestResult -TestName "sshd_config exists" -Result Pass
        
        # Test 5: sshd_config has AuthorizedKeysCommand
        $configContent = Get-Content $sshdConfigPath -Raw
        if ($configContent -match 'AuthorizedKeysCommand.*opkssh.*verify') {
            Write-TestResult -TestName "AuthorizedKeysCommand configured" -Result Pass
        } else {
            Write-TestResult -TestName "AuthorizedKeysCommand configured" -Result Fail -Message "opkssh not found in AuthorizedKeysCommand"
        }
        
        # Test 6: sshd_config has AuthorizedKeysCommandUser
        if ($configContent -match 'AuthorizedKeysCommandUser') {
            Write-TestResult -TestName "AuthorizedKeysCommandUser configured" -Result Pass
        } else {
            Write-TestResult -TestName "AuthorizedKeysCommandUser configured" -Result Fail -Message "Not found in sshd_config"
        }
        
        # Test 7: Backup exists
        $backupFiles = Get-ChildItem "C:\ProgramData\ssh\sshd_config.backup.*" -ErrorAction SilentlyContinue
        if ($backupFiles) {
            $latestBackup = $backupFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            Write-TestResult -TestName "sshd_config backup exists" -Result Pass -Message "Latest: $($latestBackup.Name)"
        } else {
            Write-TestResult -TestName "sshd_config backup exists" -Result Warning -Message "No backup found"
        }
    } else {
        Write-TestResult -TestName "sshd_config exists" -Result Fail -Message "Not found at $sshdConfigPath"
    }
}

function Test-Permissions {
    <#
    .SYNOPSIS
        Tests file permissions (requires admin).
    #>
    param()
    
    Write-Host "`nFile Permissions:" -ForegroundColor Cyan
    
    # Check if running as admin
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-TestResult -TestName "Permission checks" -Result Warning -Message "Run as Administrator for detailed permission checks"
        return
    }
    
    $configPath = "C:\ProgramData\opk"
    
    if (Test-Path $configPath) {
        try {
            $acl = Get-Acl $configPath
            
            # Check if SYSTEM has access
            $systemAccess = $acl.Access | Where-Object { $_.IdentityReference -like "*SYSTEM*" }
            if ($systemAccess) {
                Write-TestResult -TestName "SYSTEM has access" -Result Pass
            } else {
                Write-TestResult -TestName "SYSTEM has access" -Result Warning -Message "SYSTEM access not found"
            }
            
            # Check if Administrators have access
            $adminAccess = $acl.Access | Where-Object { $_.IdentityReference -like "*Administrators*" }
            if ($adminAccess) {
                Write-TestResult -TestName "Administrators have access" -Result Pass
            } else {
                Write-TestResult -TestName "Administrators have access" -Result Warning -Message "Administrators access not found"
            }
            
        } catch {
            Write-TestResult -TestName "Permission checks" -Result Warning -Message $_.Exception.Message
        }
    }
}

function Test-InstallationLog {
    <#
    .SYNOPSIS
        Checks if installation log exists.
    #>
    param()
    
    Write-Host "`nInstallation Logs:" -ForegroundColor Cyan
    
    $logPath = "C:\ProgramData\opk\logs\opkssh-install.log"
    if (Test-Path $logPath) {
        $logInfo = Get-Item $logPath
        Write-TestResult -TestName "Installation log exists" -Result Pass -Message "Last modified: $($logInfo.LastWriteTime)"
        
        # Show last few lines
        $lastLines = Get-Content $logPath -Tail 5
        if ($Verbose) {
            Write-Host "`n  Last log entries:" -ForegroundColor Gray
            $lastLines | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
        }
    } else {
        Write-TestResult -TestName "Installation log exists" -Result Warning -Message "Not found at $logPath"
    }
    
    # Check for error log
    $errorLogPath = "C:\ProgramData\opk\logs\opkssh-install-error.log"
    if (Test-Path $errorLogPath) {
        Write-TestResult -TestName "Error log check" -Result Warning -Message "Error log exists - installation may have had issues"
    } else {
        Write-TestResult -TestName "Error log check" -Result Pass -Message "No error log found"
    }
}

function Test-NetworkConnectivity {
    <#
    .SYNOPSIS
        Tests network connectivity to OpenID Providers.
    #>
    param()
    
    Write-Host "`nNetwork Connectivity:" -ForegroundColor Cyan
    
    $providers = @(
        @{ Name = "Google"; Url = "https://accounts.google.com/.well-known/openid-configuration" }
        @{ Name = "Microsoft"; Url = "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration" }
        @{ Name = "GitLab"; Url = "https://gitlab.com/.well-known/openid-configuration" }
    )
    
    foreach ($provider in $providers) {
        try {
            $null = Invoke-WebRequest -Uri $provider.Url -Method Head -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
            Write-TestResult -TestName "$($provider.Name) reachable" -Result Pass
        } catch {
            Write-TestResult -TestName "$($provider.Name) reachable" -Result Warning -Message "Cannot reach $($provider.Url)"
        }
    }
}

# Main execution
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  opkssh Installation Test Suite" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Test-BinaryInstallation
Test-ConfigurationFiles
Test-SshdConfiguration
Test-Permissions
Test-InstallationLog
Test-NetworkConnectivity

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Test Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total Tests:    $script:TotalTests" -ForegroundColor White
Write-Host "Passed:         $script:PassedTests" -ForegroundColor Green
Write-Host "Failed:         $script:FailedTests" -ForegroundColor Red
Write-Host "Warnings:       $script:WarningTests" -ForegroundColor Yellow
Write-Host ""

if ($script:FailedTests -eq 0) {
    Write-Host "All critical tests passed!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "Some tests failed. Please review the results above." -ForegroundColor Red
    exit 1
}
