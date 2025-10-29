#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Uninstalls opkssh from Windows Server.

.DESCRIPTION
    This script removes opkssh from a Windows Server installation by:
    - Restoring the original sshd_config
    - Removing the opkssh binary
    - Removing configuration files
    - Removing the opkssh user (if created)
    - Removing from system PATH

.PARAMETER KeepConfig
    Keep configuration files in C:\ProgramData\opk\ for potential reinstallation.

.PARAMETER KeepLogs
    Keep log files in C:\ProgramData\opk\logs\.

.PARAMETER NoSshdRestart
    Do not restart the sshd service after uninstallation.

.PARAMETER Force
    Skip confirmation prompts.

.EXAMPLE
    .\Uninstall-OpksshServer.ps1

.EXAMPLE
    .\Uninstall-OpksshServer.ps1 -KeepConfig -KeepLogs

.EXAMPLE
    .\Uninstall-OpksshServer.ps1 -Force

.NOTES
    Requires Administrator privileges.
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(HelpMessage="Keep configuration files")]
    [switch]$KeepConfig,

    [Parameter(HelpMessage="Keep log files")]
    [switch]$KeepLogs,

    [Parameter(HelpMessage="Do not restart sshd service")]
    [switch]$NoSshdRestart,

    [Parameter(HelpMessage="Skip confirmation prompts")]
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

function Write-UninstallLog {
    <#
    .SYNOPSIS
        Writes a message to the console and optionally to a log file.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )
    
    switch ($Level) {
        'Info'    { Write-Host $Message }
        'Warning' { Write-Warning $Message }
        'Error'   { Write-Error $Message }
        'Success' { Write-Host $Message -ForegroundColor Green }
    }
}

function Restore-SshdConfiguration {
    <#
    .SYNOPSIS
        Restores the original sshd_config from backup.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param()
    
    $sshdConfigPath = "C:\ProgramData\ssh\sshd_config"
    
    if (-not (Test-Path $sshdConfigPath)) {
        Write-UninstallLog "sshd_config not found at $sshdConfigPath" -Level Warning
        return $false
    }
    
    # Find the most recent backup
    $backupFiles = Get-ChildItem "C:\ProgramData\ssh\sshd_config.backup.*" -ErrorAction SilentlyContinue
    
    if (-not $backupFiles) {
        Write-UninstallLog "No sshd_config backup found. Manual configuration restoration required." -Level Warning
        Write-UninstallLog "Please edit $sshdConfigPath and remove the AuthorizedKeysCommand lines." -Level Warning
        return $false
    }
    
    $latestBackup = $backupFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    
    if ($PSCmdlet.ShouldProcess($sshdConfigPath, "Restore from backup: $($latestBackup.Name)")) {
        try {
            Copy-Item $latestBackup.FullName $sshdConfigPath -Force
            Write-UninstallLog "  Restored sshd_config from $($latestBackup.Name)" -Level Success
            return $true
        } catch {
            Write-UninstallLog "Failed to restore sshd_config: $($_.Exception.Message)" -Level Error
            return $false
        }
    }
    
    return $true
}

function Remove-OpksshBinary {
    <#
    .SYNOPSIS
        Removes the opkssh binary and installation directory.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param()
    
    $installDir = "C:\Program Files\opkssh"
    
    if (-not (Test-Path $installDir)) {
        Write-Verbose "Installation directory not found: $installDir"
        return $true
    }
    
    # Check if this script is running from the installation directory
    $scriptPath = $PSCommandPath
    $scriptInInstallDir = $scriptPath -and (Split-Path $scriptPath -Parent) -eq $installDir
    
    if ($PSCmdlet.ShouldProcess($installDir, "Remove directory and contents")) {
        try {
            if ($scriptInInstallDir) {
                # If this script is in the install directory, schedule it for deletion
                # and remove other files now
                Write-UninstallLog "  Scheduling uninstall script for deletion after exit" -Level Info
                
                # Remove all files except this script
                Get-ChildItem $installDir -File | Where-Object { $_.FullName -ne $scriptPath } | ForEach-Object {
                    Remove-Item $_.FullName -Force -ErrorAction Stop
                }
                
                # Create a self-delete PowerShell script
                $cleanupScript = @"
Start-Sleep -Seconds 2
Remove-Item -Path '$scriptPath' -Force -ErrorAction SilentlyContinue
Remove-Item -Path '$installDir' -Force -ErrorAction SilentlyContinue
Remove-Item -Path `$PSCommandPath -Force -ErrorAction SilentlyContinue
"@
                $cleanupPath = [System.IO.Path]::GetTempFileName() + ".ps1"
                $cleanupScript | Out-File -FilePath $cleanupPath -Encoding UTF8 -Force
                
                # Schedule the cleanup script to run in a new PowerShell process
                Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-File", "`"$cleanupPath`"" -WindowStyle Hidden
                
                Write-UninstallLog "  Removed opkssh binary from $installDir (cleanup pending)" -Level Success
            } else {
                # Script is not in the install directory, safe to delete everything
                Remove-Item $installDir -Recurse -Force -ErrorAction Stop
                Write-UninstallLog "  Removed opkssh binary from $installDir" -Level Success
            }
            return $true
        } catch {
            Write-UninstallLog "Failed to remove $installDir`: $($_.Exception.Message)" -Level Error
            return $false
        }
    }
    
    return $true
}

function Remove-OpksshConfiguration {
    <#
    .SYNOPSIS
        Removes opkssh configuration files and directories.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [bool]$KeepConfig = $false,
        [bool]$KeepLogs = $false
    )
    
    $configPath = "C:\ProgramData\opk"
    
    if (-not (Test-Path $configPath)) {
        Write-Verbose "Configuration directory not found: $configPath"
        return $true
    }
    
    if ($KeepConfig) {
        Write-UninstallLog "  Keeping configuration files (KeepConfig specified)" -Level Warning
        
        # Only remove logs if KeepLogs is not set
        if (-not $KeepLogs) {
            $logsPath = Join-Path $configPath "logs"
            if (Test-Path $logsPath) {
                if ($PSCmdlet.ShouldProcess($logsPath, "Remove logs directory")) {
                    try {
                        Remove-Item $logsPath -Recurse -Force -ErrorAction Stop
                        Write-UninstallLog "  Removed logs from $logsPath" -Level Success
                    } catch {
                        Write-UninstallLog "Failed to remove logs: $($_.Exception.Message)" -Level Warning
                    }
                }
            }
        }
        
        return $true
    }
    
    # Create a final backup of configuration before removing
    if ($PSCmdlet.ShouldProcess($configPath, "Backup before removal")) {
        try {
            $timestamp = Get-Date -Format "yyyyMMddHHmmss"
            $backupPath = "C:\ProgramData\opk-backup-$timestamp"
            Copy-Item $configPath $backupPath -Recurse -Force
            Write-UninstallLog "  Created backup at $backupPath" -Level Info
        } catch {
            Write-UninstallLog "Failed to create backup: $($_.Exception.Message)" -Level Warning
        }
    }
    
    if ($PSCmdlet.ShouldProcess($configPath, "Remove configuration directory")) {
        try {
            Remove-Item $configPath -Recurse -Force -ErrorAction Stop
            Write-UninstallLog "  Removed configuration from $configPath" -Level Success
            return $true
        } catch {
            Write-UninstallLog "Failed to remove $configPath`: $($_.Exception.Message)" -Level Error
            return $false
        }
    }
    
    return $true
}

function Remove-OpksshUser {
    <#
    .SYNOPSIS
        Removes the opkssh user account if it exists.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param()
    
    $username = "opksshuser"
    
    $user = Get-LocalUser -Name $username -ErrorAction SilentlyContinue
    
    if (-not $user) {
        Write-Verbose "User '$username' does not exist"
        return $true
    }
    
    if ($PSCmdlet.ShouldProcess($username, "Remove local user")) {
        try {
            Remove-LocalUser -Name $username -ErrorAction Stop
            Write-UninstallLog "  Removed user: $username" -Level Success
            return $true
        } catch {
            Write-UninstallLog "Failed to remove user '$username': $($_.Exception.Message)" -Level Warning
            return $false
        }
    }
    
    return $true
}

function Remove-OpksshFromPath {
    <#
    .SYNOPSIS
        Removes opkssh installation directory from system PATH without expanding environment variables.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param()
    
    $installDir = "C:\Program Files\opkssh"
    
    if ($PSCmdlet.ShouldProcess("System PATH", "Remove $installDir")) {
        try {
            # Use Registry to preserve environment variable expansion (e.g., %SystemRoot%)
            $keyName = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
            $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($keyName, $true)
            try {
                # Get current PATH without expanding environment variables
                $currentPathFolders = $key.GetValue('Path', '', 'DoNotExpandEnvironmentNames') -split [IO.Path]::PathSeparator
                
                # Normalize folder to remove
                $normalizedInstallDir = $installDir.TrimEnd([IO.Path]::DirectorySeparatorChar)
                
                # Check if in PATH
                $foundInPath = $currentPathFolders | Where-Object {
                    $_.TrimEnd([IO.Path]::DirectorySeparatorChar) -eq $normalizedInstallDir
                }
                
                if (-not $foundInPath) {
                    Write-Verbose "Installation directory not in PATH"
                    return $true
                }
                
                # Filter out the folder to remove (case-insensitive)
                $result = [Collections.Generic.HashSet[string]]::new([StringComparer]::InvariantCultureIgnoreCase)
                $currentPathFolders | 
                    Where-Object { 
                        $normalizedFolder = $_.TrimEnd([IO.Path]::DirectorySeparatorChar)
                        $normalizedFolder -ne $normalizedInstallDir
                    } | 
                    ForEach-Object { $result.Add($_) > $null }
                
                # Build new PATH and save it
                $newPath = $result -join [IO.Path]::PathSeparator
                $key.SetValue('Path', $newPath, 'ExpandString')
                
                Write-UninstallLog "  Removed from system PATH" -Level Success
                return $true
            } finally {
                if ($null -ne $key) {
                    $key.Dispose()
                }
            }
        } catch {
            Write-UninstallLog "Failed to update PATH: $($_.Exception.Message)" -Level Warning
            return $false
        }
    }
    
    return $true
}

function Restart-SshdService {
    <#
    .SYNOPSIS
        Restarts the OpenSSH Server service.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [bool]$NoRestart = $false
    )
    
    if ($NoRestart) {
        Write-Warning "Skipping sshd service restart (NoRestart specified)"
        Write-Warning "You must manually restart the sshd service:"
        Write-Warning "  Restart-Service sshd"
        return $true
    }
    
    if ($PSCmdlet.ShouldProcess("sshd", "Restart service")) {
        try {
            Restart-Service sshd -Force -ErrorAction Stop
            
            Start-Sleep -Seconds 2
            
            $service = Get-Service sshd
            if ($service.Status -eq 'Running') {
                Write-UninstallLog "  sshd service restarted successfully" -Level Success
                return $true
            } else {
                throw "Service is in state: $($service.Status)"
            }
        } catch {
            Write-UninstallLog "Failed to restart sshd service: $($_.Exception.Message)" -Level Warning
            Write-Warning "Please restart the service manually: Restart-Service sshd"
            return $false
        }
    }
    
    return $true
}

# Main uninstallation logic
try {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  opkssh Uninstallation for Windows" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Confirmation (unless -Force is specified)
    if (-not $Force) {
        Write-Host "This will remove opkssh from your system." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "The following items will be removed:" -ForegroundColor Yellow
        Write-Host "  - opkssh binary (C:\Program Files\opkssh\)" -ForegroundColor White
        
        if (-not $KeepConfig) {
            Write-Host "  - Configuration files (C:\ProgramData\opk\)" -ForegroundColor White
        } else {
            Write-Host "  - Configuration files (KEPT - KeepConfig specified)" -ForegroundColor Green
        }
        
        Write-Host "  - sshd_config modifications (restored from backup)" -ForegroundColor White
        Write-Host "  - opksshuser account (if exists)" -ForegroundColor White
        Write-Host "  - System PATH entry" -ForegroundColor White
        Write-Host ""
        
        $confirmation = Read-Host "Are you sure you want to continue? (yes/no)"
        if ($confirmation -ne 'yes') {
            Write-Host "Uninstallation cancelled." -ForegroundColor Yellow
            exit 0
        }
        Write-Host ""
    }
    
    # Step 1: Restore sshd configuration
    Write-Host "[1/6] Restoring sshd_config..." -ForegroundColor Yellow
    Restore-SshdConfiguration | Out-Null
    Write-Host ""
    
    # Step 2: Remove binary
    Write-Host "[2/6] Removing opkssh binary..." -ForegroundColor Yellow
    Remove-OpksshBinary | Out-Null
    Write-Host ""
    
    # Step 3: Remove configuration
    Write-Host "[3/6] Removing configuration..." -ForegroundColor Yellow
    Remove-OpksshConfiguration -KeepConfig $KeepConfig -KeepLogs $KeepLogs | Out-Null
    Write-Host ""
    
    # Step 4: Remove user
    Write-Host "[4/6] Removing opkssh user..." -ForegroundColor Yellow
    Remove-OpksshUser | Out-Null
    Write-Host ""
    
    # Step 5: Remove from PATH
    Write-Host "[5/6] Removing from system PATH..." -ForegroundColor Yellow
    Remove-OpksshFromPath | Out-Null
    Write-Host ""
    
    # Step 6: Restart sshd
    Write-Host "[6/6] Restarting sshd service..." -ForegroundColor Yellow
    Restart-SshdService -NoRestart $NoSshdRestart | Out-Null
    Write-Host ""
    
    # Success message
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  Uninstallation Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    
    if ($KeepConfig) {
        Write-Host "Configuration files preserved at: C:\ProgramData\opk\" -ForegroundColor Cyan
        Write-Host ""
    }
    
    Write-Host "opkssh has been removed from your system." -ForegroundColor White
    Write-Host ""
    
} catch {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "  Uninstallation Failed" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Stack Trace:" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Gray
    Write-Host ""
    
    throw
}
