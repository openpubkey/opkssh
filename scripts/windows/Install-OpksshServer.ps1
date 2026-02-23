#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Installs and configures opkssh on Windows Server 2022 with OpenSSH Server.

.DESCRIPTION
    This script downloads and installs the opkssh binary, creates necessary configuration
    files and directories, and configures the OpenSSH Server to use opkssh for
    authentication via OpenID Connect.

.PARAMETER NoSshdRestart
    Do not restart the sshd service after installation.
    You must manually restart the service for changes to take effect.

.PARAMETER OverwriteConfig
    Overwrite existing AuthorizedKeysCommand configuration in sshd_config.
    Use this if the script detects existing configuration that conflicts.

.PARAMETER InstallFrom
    Path to a local opkssh.exe file to install instead of downloading from GitHub.

.PARAMETER InstallVersion
    Specific version to install from GitHub (e.g., "v0.10.0").
    Default is "latest".

.PARAMETER InstallDir
    Directory where opkssh.exe will be installed.
    Default is "C:\Program Files\opkssh".

.PARAMETER ConfigPath
    Directory where opkssh configuration files will be created.
    Default is "C:\ProgramData\opk".

.PARAMETER AuthCmdUser
    User account that will run the AuthorizedKeysCommand.
    Default is "System" (the OpenSSH service account).
    You can specify "opksshuser" to create a dedicated local user instead.

.PARAMETER GitHubRepo
    GitHub repository to download from (format: owner/repo).
    Default is "openpubkey/opkssh".

.EXAMPLE
    .\Install-OpksshServer.ps1
    
    Basic installation with default settings.

.EXAMPLE
    .\Install-OpksshServer.ps1 -InstallFrom "C:\Downloads\opkssh.exe"
    
    Install from a local file instead of downloading.

.EXAMPLE
    .\Install-OpksshServer.ps1 -InstallVersion "v0.10.0" -Verbose
    
    Install a specific version with verbose output.

.EXAMPLE
    .\Install-OpksshServer.ps1 -AuthCmdUser "opksshuser"
    
    Install using a dedicated local user account instead of System.

.NOTES
    Author: OpenPubkey Project
    Requires: Windows Server 2022 (or Windows 10/11 with OpenSSH Server installed)
    Requires: PowerShell 5.1 or higher
    Requires: Administrator privileges
    Requires: OpenSSH Server installed and configured
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(HelpMessage="Do not restart sshd service after installation")]
    [switch]$NoSshdRestart,

    [Parameter(HelpMessage="Overwrite existing AuthorizedKeysCommand configuration")]
    [switch]$OverwriteConfig,

    [Parameter(HelpMessage="Path to local opkssh.exe file")]
    [ValidateScript({
        if ($_ -and -not (Test-Path $_)) {
            throw "File not found: $_"
        }
        $true
    })]
    [string]$InstallFrom = "",

    [Parameter(HelpMessage="Version to install (e.g., 'v0.10.0' or 'latest')")]
    [string]$InstallVersion = "latest",

    [Parameter(HelpMessage="Installation directory for opkssh.exe")]
    [string]$InstallDir = "C:\Program Files\opkssh",

    [Parameter(HelpMessage="Configuration directory path")]
    [string]$ConfigPath = "C:\ProgramData\opk",

    [Parameter(HelpMessage="User account for AuthorizedKeysCommand")]
    [ValidateSet("System", "opksshuser")]
    [string]$AuthCmdUser = "System",

    [Parameter(HelpMessage="GitHub repository (owner/repo)")]
    [string]$GitHubRepo = "openpubkey/opkssh"
)

#region Helper Functions

function Write-Log {
    <#
    .SYNOPSIS
        Writes a message to the console and optionally to a log file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet('Info', 'Warning', 'Error', 'Success', 'Verbose')]
        [string]$Level = 'Info',
        
        [Parameter()]
        [string]$LogFile
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        'Info'    { Write-Host $Message }
        'Warning' { Write-Warning $Message }
        'Error'   { Write-Error $Message }
        'Success' { Write-Host $Message -ForegroundColor Green }
        'Verbose' { Write-Verbose $Message }
    }
    
    if ($LogFile -and (Test-Path (Split-Path $LogFile -Parent))) {
        Add-Content -Path $LogFile -Value $logMessage
    }
}

function Test-Prerequisites {
    <#
    .SYNOPSIS
        Verifies that all prerequisites are met for installation.
    #>
    [CmdletBinding()]
    param()
    
    Write-Verbose "Checking prerequisites..."
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        throw "PowerShell 5.1 or higher is required. Current version: $($PSVersionTable.PSVersion)"
    }
    Write-Verbose "  PowerShell version: $($PSVersionTable.PSVersion)"
    
    # Check if running as Administrator
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        throw "This script must be run as Administrator. Please restart PowerShell with elevated privileges."
    }
    Write-Verbose "  Running with Administrator privileges: OK"
    
    # Check OpenSSH Server capability
    Write-Verbose "  Checking OpenSSH Server installation..."
    $sshCapability = Get-WindowsCapability -Online -Name "OpenSSH.Server*" -ErrorAction SilentlyContinue
    
    if (-not $sshCapability) {
        throw "OpenSSH Server capability not found. This script requires Windows Server 2019 or later, or Windows 10/11."
    }
    
    if ($sshCapability.State -ne 'Installed') {
        throw "OpenSSH Server is not installed. Install it using: Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"
    }
    Write-Verbose "  OpenSSH Server is installed"
    
    # Check sshd service
    $sshdService = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if (-not $sshdService) {
        throw "sshd service not found. OpenSSH Server may not be properly configured."
    }
    Write-Verbose "  sshd service found: $($sshdService.Status)"
    
    # Check OpenSSH version when using System account
    if ($AuthCmdUser -eq "System") {
        Write-Verbose "  Validating OpenSSH version for LocalSystem account..."
        
        try {
            $canUseSystemAccount = (Get-Command sshd).Version -ge [version]'8.9'
        } catch {
            throw "Unexpected: sshd.exe not in PATH?"
        }
        
        $sshdVersion = (Get-Command sshd).Version
        Write-Verbose "  Detected OpenSSH Server version: $sshdVersion"
        
        if (-not $canUseSystemAccount) {
            $errorMessage = @"

========================================
ERROR: OpenSSH Version Too Old
========================================

Your OpenSSH Server version ($sshdVersion) does not support using 'LocalSystem' 
as the AuthorizedKeysCommandUser.

OpenSSH Server 8.9.0 or higher is required to use the LocalSystem account.

SOLUTION:
Run the installer with the -AuthCmdUser parameter:

    .\Install-OpksshServer.ps1 -AuthCmdUser "opksshuser"

This will create and use a dedicated 'opksshuser' account instead.

========================================
"@
            throw $errorMessage
        }
        
        Write-Verbose "  OpenSSH version is compatible with LocalSystem account"
    } else {
        Write-Verbose "  Using custom user account, no version restriction"
    }
    
    # Verify sshd_config exists
    $sshdConfigPath = "C:\ProgramData\ssh\sshd_config"
    if (-not (Test-Path $sshdConfigPath)) {
        throw "sshd_config not found at $sshdConfigPath"
    }
    Write-Verbose "  sshd_config found at: $sshdConfigPath"
    
    Write-Verbose "All prerequisites met."
    return $true
}

function Get-SystemArchitecture {
    <#
    .SYNOPSIS
        Determines the CPU architecture of the system.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    
    $arch = $env:PROCESSOR_ARCHITECTURE
    Write-Verbose "Detected processor architecture: $arch"
    
    switch ($arch) {
        "AMD64" { 
            Write-Verbose "Using architecture: amd64"
            return "amd64" 
        }
        "ARM64" { 
            Write-Verbose "Using architecture: arm64"
            return "arm64" 
        }
        default { 
            throw "Unsupported CPU architecture: $arch. Supported architectures are AMD64 and ARM64."
        }
    }
}

function Test-OpksshVersion {
    <#
    .SYNOPSIS
        Validates that the requested version is supported by this script.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Version
    )
    
    if ($Version -eq "latest") {
        Write-Verbose "Installing latest version"
        return $true
    }
    
    # Minimum supported version
    $minVersionString = "0.10.0"
    $minVersion = [version]$minVersionString
    
    # Parse requested version (allow optional prerelease/build suffixes)
    $versionMatch = [regex]::Match($Version, '^v?(?<core>\d+\.\d+\.\d+)(?<suffix>[-+].+)?$')
    if (-not $versionMatch.Success) {
        throw "Invalid version format: $Version. Use format 'v0.10.0' or '0.10.0' (optionally with -suffix)"
    }
    
    $versionString = $versionMatch.Groups['core'].Value
    
    try {
        $requestedVersion = [version]$versionString
    } catch {
        throw "Invalid version format: $Version. Use format 'v0.10.0' or '0.10.0' (optionally with -suffix)"
    }
    
    if ($requestedVersion -lt $minVersion) {
        throw @"
Installing opkssh $Version with this script is not supported.
Minimum supported version is v$minVersionString.
For older versions, please use the installation script from that release.
"@
    }
    
    Write-Verbose "Version $Version is supported"
    return $true
}

function New-OpksshUser {
    <#
    .SYNOPSIS
        Creates a dedicated local user account for running AuthorizedKeysCommand.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Username
    )
    
    if ($Username -eq "System") {
        Write-Verbose "Using built-in service account: System"
        return $true
    }
    
    Write-Verbose "Checking if user '$Username' exists..."
    $existingUser = Get-LocalUser -Name $Username -ErrorAction SilentlyContinue
    
    if ($existingUser) {
        Write-Verbose "User '$Username' already exists"
        return $true
    }
    
    if ($PSCmdlet.ShouldProcess($Username, "Create local user")) {
        Write-Verbose "Creating local user: $Username"
        
        # Generate a random password
        Add-Type -AssemblyName 'System.Web'
        $password = [System.Web.Security.Membership]::GeneratePassword(32, 10)
        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
        
        # Create user with security settings
        try {
            New-LocalUser -Name $Username `
                         -Password $securePassword `
                         -Description "OpenPubkey SSH verification user" `
                         -UserMayNotChangePassword `
                         -PasswordNeverExpires `
                         -AccountNeverExpires `
                         -ErrorAction Stop | Out-Null
            
            Write-Log "Created user: $Username" -Level Success
            
            # Note: Denying interactive logon requires editing local security policy
            # This would typically be done via secedit or Group Policy
            Write-Warning "Manual step required: Deny interactive logon rights for user '$Username' via Local Security Policy"
            
        } catch {
            throw "Failed to create user '$Username': $($_.Exception.Message)"
        }
    }
    
    return $true
}

function Install-OpksshBinary {
    <#
    .SYNOPSIS
        Downloads or copies the opkssh binary to the installation directory.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)]
        [string]$InstallDir,
        
        [Parameter()]
        [string]$LocalFile,
        
        [Parameter(Mandatory=$true)]
        [string]$Version,
        
        [Parameter(Mandatory=$true)]
        [string]$Architecture,
        
        [Parameter(Mandatory=$true)]
        [string]$GitHubRepo
    )
    
    $binaryName = "opkssh.exe"
    $binaryPath = Join-Path $InstallDir $binaryName
    
    # Create installation directory if it doesn't exist
    if (-not (Test-Path $InstallDir)) {
        Write-Verbose "Creating installation directory: $InstallDir"
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }
    
    if ($LocalFile) {
        # Install from local file
        Write-Log "Installing from local file: $LocalFile"
        
        if (-not (Test-Path $LocalFile)) {
            throw "Local file not found: $LocalFile"
        }
        
        if ($PSCmdlet.ShouldProcess($LocalFile, "Copy to $binaryPath")) {
            Copy-Item $LocalFile $binaryPath -Force
            Write-Verbose "Copied $LocalFile to $binaryPath"
        }
    } else {
        # Download from GitHub
        if ($Version -eq "latest") {
            $downloadUrl = "https://github.com/$GitHubRepo/releases/latest/download/opkssh-windows-$Architecture.exe"
        } else {
            $downloadUrl = "https://github.com/$GitHubRepo/releases/download/$Version/opkssh-windows-$Architecture.exe"
        }
        
        Write-Log "Downloading opkssh version $Version from GitHub..."
        Write-Verbose "Download URL: $downloadUrl"
        
        if ($PSCmdlet.ShouldProcess($downloadUrl, "Download to $binaryPath")) {
            try {
                # Use TLS 1.2
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                
                # Download with progress
                $ProgressPreference = 'SilentlyContinue'
                Invoke-WebRequest -Uri $downloadUrl -OutFile $binaryPath -UseBasicParsing -ErrorAction Stop
                $ProgressPreference = 'Continue'
                
                Write-Verbose "Downloaded to: $binaryPath"
            } catch {
                throw "Failed to download opkssh binary: $($_.Exception.Message)"
            }
        }
    }
    
    # Verify the binary exists and is executable
    if (-not (Test-Path $binaryPath)) {
        throw "Installation failed: Binary not found at $binaryPath"
    }
    
    $fileInfo = Get-Item $binaryPath
    Write-Verbose "Binary size: $($fileInfo.Length) bytes"
    
    # Test that the binary is valid by running --version
    try {
        $versionOutput = & $binaryPath --version 2>&1
        Write-Verbose "Binary version: $versionOutput"
    } catch {
        Write-Warning "Could not verify binary version: $($_.Exception.Message)"
    }
    
    Write-Log "Installed opkssh to: $binaryPath" -Level Success
    return $binaryPath
}

function Install-UninstallScript {
    <#
    .SYNOPSIS
        Downloads the uninstall script and places it in the installation directory.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)]
        [string]$InstallDir,
        
        [Parameter(Mandatory=$true)]
        [string]$Version,
        
        [Parameter(Mandatory=$true)]
        [string]$GitHubRepo
    )
    
    $scriptName = "Uninstall-OpksshServer.ps1"
    $scriptPath = Join-Path $InstallDir $scriptName
    
    # Download from GitHub
    if ($Version -eq "latest") {
        $downloadUrl = "https://github.com/$GitHubRepo/releases/latest/download/$scriptName"
    } else {
        $downloadUrl = "https://github.com/$GitHubRepo/releases/download/$Version/$scriptName"
    }
    
    Write-Log "Downloading uninstall script..."
    Write-Verbose "Download URL: $downloadUrl"
    
    if ($PSCmdlet.ShouldProcess($downloadUrl, "Download to $scriptPath")) {
        try {
            # Use TLS 1.2
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            
            # Download with progress
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri $downloadUrl -OutFile $scriptPath -UseBasicParsing -ErrorAction Stop
            $ProgressPreference = 'Continue'
            
            Write-Log "Installed uninstall script to: $scriptPath" -Level Success
            Write-Verbose "Downloaded to: $scriptPath"
        } catch {
            # Non-fatal error - uninstall script is optional
            Write-Warning "Could not download uninstall script: $($_.Exception.Message)"
            Write-Warning "You can manually download it from: $downloadUrl"
            return $null
        }
    }
    
    return $scriptPath
}

function New-OpksshConfiguration {
    <#
    .SYNOPSIS
        Creates opkssh configuration directory structure and files.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConfigPath,
        
        [Parameter(Mandatory=$true)]
        [string]$AuthCmdUser
    )
    
    Write-Log "Configuring opkssh at: $ConfigPath"
    
    # Define directory structure
    $directories = @(
        $ConfigPath,
        (Join-Path $ConfigPath "policy.d"),
        (Join-Path $ConfigPath "logs")
    )
    
    # Create directories
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            if ($PSCmdlet.ShouldProcess($dir, "Create directory")) {
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
                Write-Verbose "  Created directory: $dir"
            }
        } else {
            Write-Verbose "  Directory exists: $dir"
        }
    }
    
    # Define configuration files
    $authIdPath = Join-Path $ConfigPath "auth_id"
    $configYmlPath = Join-Path $ConfigPath "config.yml"
    $providersPath = Join-Path $ConfigPath "providers"
    
    # Create auth_id if it doesn't exist
    if (-not (Test-Path $authIdPath)) {
        if ($PSCmdlet.ShouldProcess($authIdPath, "Create auth_id file")) {
            New-Item -ItemType File -Path $authIdPath -Force | Out-Null
            Write-Verbose "  Created file: auth_id"
        }
    } else {
        Write-Verbose "  File exists: auth_id"
    }
    
    # Create config.yml if it doesn't exist
    if (-not (Test-Path $configYmlPath)) {
        if ($PSCmdlet.ShouldProcess($configYmlPath, "Create config.yml file")) {
            New-Item -ItemType File -Path $configYmlPath -Force | Out-Null
            Write-Verbose "  Created file: config.yml"
        }
    } else {
        Write-Verbose "  File exists: config.yml"
    }
    
    # Create or update providers file
    if (-not (Test-Path $providersPath)) {
        $providersContent = @"
# Issuer Client-ID expiration-policy
https://accounts.google.com 206584157355-7cbe4s640tvm7naoludob4ut1emii7sf.apps.googleusercontent.com 24h
https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0 096ce0a3-5e72-4da8-9c86-12924b294a01 24h
https://gitlab.com 8d8b7024572c7fd501f64374dec6bba37096783dfcd792b3988104be08cb6923 24h
https://issuer.hello.coop app_xejobTKEsDNSRd5vofKB2iay_2rN 24h
"@
        
        if ($PSCmdlet.ShouldProcess($providersPath, "Create providers file")) {
            Set-Content -Path $providersPath -Value $providersContent -NoNewline
            Write-Verbose "  Created file: providers"
        }
    } else {
        $existingContent = Get-Content $providersPath -Raw
        if ([string]::IsNullOrWhiteSpace($existingContent)) {
            Write-Warning "  The providers file exists but is empty. Keeping it empty."
        } else {
            Write-Verbose "  The providers file is not empty. Keeping existing values."
        }
    }
    
    Write-Log "Configuration created successfully" -Level Success
    return $true
}

function Set-SshdConfiguration {
    <#
    .SYNOPSIS
        Configures sshd_config to use opkssh for AuthorizedKeysCommand.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)]
        [string]$BinaryPath,
        
        [Parameter(Mandatory=$true)]
        [string]$AuthCmdUser,
        
        [Parameter()]
        [bool]$OverwriteConfig = $false,

        [Parameter()]
        [string]$SshdConfigPath = "C:\ProgramData\ssh\sshd_config"
    )

    Write-Log "Configuring OpenSSH Server..."
    Write-Verbose "  sshd_config path: $sshdConfigPath"
    
    if (-not (Test-Path $sshdConfigPath)) {
        throw "sshd_config not found at: $sshdConfigPath"
    }
    
    # Read current configuration
    $configLines = Get-Content $sshdConfigPath

    # Prepare new configuration lines
    # Note: Windows paths with spaces must be quoted
    $quotedBinaryPath = "`"$BinaryPath`""
    $authKeyCmdLine = "AuthorizedKeysCommand $quotedBinaryPath verify %u %k %t"
    $authKeyUserLine = "AuthorizedKeysCommandUser $AuthCmdUser"
    
    # Check for existing AuthorizedKeysCommand configuration
    $hasAuthKeyCmd = $configLines | Where-Object { 
        $_ -match '^\s*AuthorizedKeysCommand\s+' -and $_ -notmatch '^\s*#' 
    }
    $hasAuthKeyUser = $configLines | Where-Object { 
        $_ -match '^\s*AuthorizedKeysCommandUser\s+' -and $_ -notmatch '^\s*#' 
    }
    
    $matchesAuthKeyCmd = $hasAuthKeyCmd | Where-Object { $_.Trim() -eq $authKeyCmdLine }
    $matchesAuthKeyUser = $hasAuthKeyUser | Where-Object { $_.Trim() -eq $authKeyUserLine }

    if ($matchesAuthKeyCmd -and $matchesAuthKeyUser) {
        Write-Log "  Existing opkssh sshd_config entries already match desired configuration" -Level Success
        return $true
    }

    if (($hasAuthKeyCmd -or $hasAuthKeyUser) -and -not $OverwriteConfig) {
        Write-Warning "Existing AuthorizedKeysCommand configuration detected:"
        $hasAuthKeyCmd | ForEach-Object { Write-Warning "  $_" }
        $hasAuthKeyUser | ForEach-Object { Write-Warning "  $_" }
        Write-Warning ""
        Write-Warning "To overwrite this configuration, run the script with -OverwriteConfig"
        return $false
    }

    # Backup existing configuration
    $timestamp = Get-Date -Format "yyyyMMddHHmmss"
    $backupPath = "$sshdConfigPath.backup.$timestamp"

    if ($PSCmdlet.ShouldProcess($sshdConfigPath, "Create backup at $backupPath")) {
        Copy-Item $sshdConfigPath $backupPath -Force
        Write-Verbose "  Created backup: $backupPath"
    }
    
    # Process configuration
    $newConfigLines = @()
    
    foreach ($line in $configLines) {
        if ($line -match '^\s*AuthorizedKeysCommand\s+') {
            # Comment out existing AuthorizedKeysCommand
            $newConfigLines += "# $line"
            Write-Verbose "  Commented out: $line"
        } elseif ($line -match '^\s*AuthorizedKeysCommandUser\s+') {
            # Comment out existing AuthorizedKeysCommandUser
            $newConfigLines += "# $line"
            Write-Verbose "  Commented out: $line"
        } else {
            $newConfigLines += $line
        }
    }
    
    # Add opkssh configuration at the end
    $newConfigLines += ""
    $newConfigLines += "# opkssh configuration - added by Install-OpksshServer.ps1 on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $newConfigLines += $authKeyCmdLine
    $newConfigLines += $authKeyUserLine
    
    # Write new configuration
    if ($PSCmdlet.ShouldProcess($sshdConfigPath, "Update sshd_config")) {
        Set-Content -Path $sshdConfigPath -Value $newConfigLines -Force
        Write-Verbose "  Updated sshd_config"
    }
    
    # Validate configuration by attempting to parse it
    # Note: OpenSSH on Windows doesn't have a built-in config test like sshd -t
    # We'll do a basic sanity check
    Write-Verbose "  Validating configuration..."
    $finalConfig = Get-Content $sshdConfigPath -Raw
    if ($finalConfig -match [regex]::Escape($authKeyCmdLine)) {
        Write-Log "  OpenSSH Server configured successfully" -Level Success
        return $true
    } else {
        Write-Error "Configuration validation failed"
        if ($PSCmdlet.ShouldProcess($backupPath, "Restore from backup")) {
            Copy-Item $backupPath $sshdConfigPath -Force
            Write-Warning "Restored configuration from backup"
        }
        return $false
    }
}

function Restart-SshdService {
    <#
    .SYNOPSIS
        Restarts the OpenSSH Server (sshd) service.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter()]
        [bool]$NoRestart = $false
    )
    
    if ($NoRestart) {
        Write-Warning "Skipping sshd service restart (NoRestart parameter specified)"
        Write-Warning "You must manually restart the sshd service for changes to take effect:"
        Write-Warning "  Restart-Service sshd"
        return $true
    }
    
    Write-Log "Restarting sshd service..."
    
    if ($PSCmdlet.ShouldProcess("sshd", "Restart service")) {
        try {
            Restart-Service sshd -Force -ErrorAction Stop
            
            # Wait a moment for service to stabilize
            Start-Sleep -Seconds 2
            
            # Verify service is running
            $service = Get-Service sshd
            if ($service.Status -eq 'Running') {
                Write-Log "  sshd service restarted successfully" -Level Success
                
                # Ensure service starts automatically
                $startType = (Get-Service sshd).StartType
                if ($startType -ne 'Automatic') {
                    Set-Service sshd -StartupType Automatic
                    Write-Verbose "  Set sshd service to start automatically"
                }
                
                return $true
            } else {
                throw "Service is in state: $($service.Status)"
            }
        } catch {
            Write-Error "Failed to restart sshd service: $($_.Exception.Message)"
            Write-Warning "Please restart the service manually: Restart-Service sshd"
            return $false
        }
    }
    
    return $true
}

function Add-OpksshToPath {
    <#
    .SYNOPSIS
        Adds opkssh installation directory to the system PATH without expanding environment variables.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)]
        [string]$InstallDir
    )
    
    if ($PSCmdlet.ShouldProcess("System PATH", "Add $InstallDir")) {
        try {
            # Use Registry to preserve environment variable expansion (e.g., %SystemRoot%)
            $keyName = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
            $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($keyName, $true)
            try {
                # Get current PATH without expanding environment variables
                $currentPathFolders = $key.GetValue('Path', '', 'DoNotExpandEnvironmentNames') -split [IO.Path]::PathSeparator
                
                # Check if already in PATH (case-insensitive)
                $normalizedInstallDir = $InstallDir.TrimEnd([IO.Path]::DirectorySeparatorChar)
                $alreadyInPath = $currentPathFolders | Where-Object {
                    $_.TrimEnd([IO.Path]::DirectorySeparatorChar) -eq $normalizedInstallDir
                }
                
                if ($alreadyInPath) {
                    Write-Verbose "Installation directory already in PATH"
                    return $true
                }
                
                # Add new folder to the current PATH
                $newPathFolders = $currentPathFolders + @($normalizedInstallDir)
                
                # Normalize folders to remove trailing slashes and duplicates
                $result = [Collections.Generic.HashSet[string]]::new([StringComparer]::InvariantCultureIgnoreCase)
                $newPathFolders |
                    ForEach-Object {
                        $normalized = $_.TrimEnd([IO.Path]::DirectorySeparatorChar).Trim()
                        if ($normalized -ne '') {
                            $result.Add($normalized) > $null
                        }
                    }
                
                # Build new PATH and save it
                $newPath = $result -join [IO.Path]::PathSeparator
                $key.SetValue('Path', $newPath, 'ExpandString')
                
                Write-Log "  Added to system PATH: $InstallDir" -Level Success
                Write-Warning "You may need to restart your PowerShell session for PATH changes to take effect"
                return $true
            } finally {
                if ($null -ne $key) {
                    $key.Dispose()
                }
            }
        } catch {
            Write-Warning "Failed to add to PATH: $($_.Exception.Message)"
            Write-Warning "You can manually add '$InstallDir' to your PATH"
            return $false
        }
    }
    
    return $true
}

function Write-InstallationLog {
    <#
    .SYNOPSIS
        Logs installation details to a file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$LogPath,
        
        [Parameter(Mandatory=$true)]
        [string]$BinaryPath,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$InstallParams
    )
    
    # Ensure log directory exists
    $logDir = Split-Path $LogPath -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    
    # Get version from binary
    try {
        $version = & $BinaryPath --version 2>&1
    } catch {
        $version = "Unknown (failed to execute --version)"
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    $logEntry = @"

========================================
opkssh Installation Log
========================================
Timestamp: $timestamp
Version: $version
Binary Path: $BinaryPath
Install Version Parameter: $($InstallParams.InstallVersion)
Local Install File: $($InstallParams.InstallFrom)
SSH Restarted: $(-not $InstallParams.NoRestart)
Auth Command User: $($InstallParams.AuthCmdUser)
Configuration Path: $($InstallParams.ConfigPath)
PowerShell Version: $($PSVersionTable.PSVersion)
OS Version: $([System.Environment]::OSVersion.VersionString)
Computer Name: $env:COMPUTERNAME
User: $env:USERNAME
========================================

"@
    
    try {
        Add-Content -Path $LogPath -Value $logEntry -ErrorAction Stop
        Write-Verbose "Installation logged to: $LogPath"
    } catch {
        Write-Warning "Failed to write installation log: $($_.Exception.Message)"
    }
}

#endregion Helper Functions

#region Main Installation Logic

function Install-OpksshServer {
    <#
    .SYNOPSIS
        Main installation function.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param()
    
    $ErrorActionPreference = 'Stop'
    
    try {
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "  opkssh Installation for Windows" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host ""
        
        # Step 1: Verify prerequisites
        Write-Host "[1/10] Checking prerequisites..." -ForegroundColor Yellow
        Test-Prerequisites | Out-Null
        Write-Host "  Prerequisites OK" -ForegroundColor Green
        Write-Host ""
        
        # Step 2: Get system architecture
        Write-Host "[2/10] Detecting system architecture..." -ForegroundColor Yellow
        $arch = Get-SystemArchitecture
        Write-Host "  Architecture: $arch" -ForegroundColor Green
        Write-Host ""
        
        # Step 3: Validate version
        Write-Host "[3/10] Validating opkssh version..." -ForegroundColor Yellow
        Test-OpksshVersion -Version $InstallVersion | Out-Null
        Write-Host "  Version OK: $InstallVersion" -ForegroundColor Green
        Write-Host ""
        
        # Step 4: Create user account (if needed)
        Write-Host "[4/10] Configuring authentication user..." -ForegroundColor Yellow
        New-OpksshUser -Username $AuthCmdUser | Out-Null
        Write-Host "  Auth user: $AuthCmdUser" -ForegroundColor Green
        Write-Host ""
        
        # Step 5: Install binary
        Write-Host "[5/10] Installing opkssh binary..." -ForegroundColor Yellow
        $binaryPath = Install-OpksshBinary -InstallDir $InstallDir `
                                           -LocalFile $InstallFrom `
                                           -Version $InstallVersion `
                                           -Architecture $arch `
                                           -GitHubRepo $GitHubRepo
        Write-Host "  Installed: $binaryPath" -ForegroundColor Green
        Write-Host ""
        
        # Step 6: Install uninstall script
        Write-Host "[6/10] Installing uninstall script..." -ForegroundColor Yellow
        $uninstallPath = Install-UninstallScript -InstallDir $InstallDir `
                                                  -Version $InstallVersion `
                                                  -GitHubRepo $GitHubRepo
        if ($uninstallPath) {
            Write-Host "  Installed: $uninstallPath" -ForegroundColor Green
        } else {
            Write-Host "  Uninstall script not available (optional)" -ForegroundColor Yellow
        }
        Write-Host ""
        
        # Step 7: Create configuration
        Write-Host "[7/11] Creating configuration..." -ForegroundColor Yellow
        New-OpksshConfiguration -ConfigPath $ConfigPath -AuthCmdUser $AuthCmdUser | Out-Null
        Write-Host "  Configuration: $ConfigPath" -ForegroundColor Green
        Write-Host ""
        
        # Step 8: Configure permissions using opkssh
        Write-Host "[8/11] Configuring file permissions..." -ForegroundColor Yellow
        $permArgs = @("permissions", "install")
        if ($Verbose) {
            $permArgs += "-v"
        }
        
        try {
            & $binaryPath $permArgs
            
            if ($LASTEXITCODE -ne 0) {
                Write-Warning "Permission configuration returned non-zero exit code but continuing..."
            } else {
                Write-Host "  Permissions configured successfully" -ForegroundColor Green
            }
        } catch {
            Write-Warning "Failed to configure permissions: $($_.Exception.Message)"
            Write-Warning "You may need to run: & '$binaryPath' permissions fix"
        }
        Write-Host ""
        
        # Step 9: Configure sshd
        Write-Host "[9/11] Configuring OpenSSH Server..." -ForegroundColor Yellow
        $sshdConfigResult = Set-SshdConfiguration -BinaryPath $binaryPath `
                                                   -AuthCmdUser $AuthCmdUser `
                                                   -OverwriteConfig $OverwriteConfig
        if (-not $sshdConfigResult) {
            throw "Failed to configure sshd_config"
        }
        Write-Host "  sshd_config updated" -ForegroundColor Green
        Write-Host ""
        
        # Step 10: Restart sshd service
        Write-Host "[10/11] Restarting OpenSSH Server..." -ForegroundColor Yellow
        Restart-SshdService -NoRestart $NoSshdRestart | Out-Null
        if (-not $NoSshdRestart) {
            Write-Host "  Service restarted" -ForegroundColor Green
        } else {
            Write-Host "  Service restart skipped" -ForegroundColor Yellow
        }
        Write-Host ""
        
        # Step 11: Add to PATH and log
        Write-Host "[11/11] Finalizing installation..." -ForegroundColor Yellow
        Add-OpksshToPath -InstallDir $InstallDir | Out-Null
        
        $logPath = Join-Path $ConfigPath "logs\opkssh-install.log"
        Write-InstallationLog -LogPath $logPath `
                              -BinaryPath $binaryPath `
                              -InstallParams @{
                                  InstallVersion = $InstallVersion
                                  InstallFrom = $InstallFrom
                                  NoRestart = $NoSshdRestart
                                  AuthCmdUser = $AuthCmdUser
                                  ConfigPath = $ConfigPath
                              }
        Write-Host "  Installation log: $logPath" -ForegroundColor Green
        Write-Host ""
        
        # Success message
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "  Installation Successful!" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Next steps:" -ForegroundColor Cyan
        Write-Host "  1. Authorize users to access this server:" -ForegroundColor White
        Write-Host "       & '$binaryPath' add <username> <email> <issuer>" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  2. Example - Allow alice@gmail.com to SSH as 'Administrator':" -ForegroundColor White
        Write-Host "       & '$binaryPath' add Administrator alice@gmail.com google" -ForegroundColor Gray
        Write-Host ""
        
        if ($uninstallPath) {
            Write-Host "  3. To uninstall opkssh:" -ForegroundColor White
            Write-Host "       & '$uninstallPath'" -ForegroundColor Gray
            Write-Host ""
        }

        Write-Host "Documentation: https://github.com/openpubkey/opkssh" -ForegroundColor White
        Write-Host ""
        
    } catch {
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Red
        Write-Host "  Installation Failed" -ForegroundColor Red
        Write-Host "========================================" -ForegroundColor Red
        Write-Host ""
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        Write-Host "Stack Trace:" -ForegroundColor Red
        Write-Host $_.ScriptStackTrace -ForegroundColor Gray
        Write-Host ""
        
        # Log error
        $errorLogPath = Join-Path $ConfigPath "logs\opkssh-install-error.log"
        try {
            $errorDir = Split-Path $errorLogPath -Parent
            if (-not (Test-Path $errorDir)) {
                New-Item -ItemType Directory -Path $errorDir -Force | Out-Null
            }
            
            $errorDetails = @"

========================================
Installation Error Log
========================================
Timestamp: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Error Message: $($_.Exception.Message)
Stack Trace:
$($_.ScriptStackTrace)
========================================

"@
            Add-Content -Path $errorLogPath -Value $errorDetails
            Write-Host "Error details logged to: $errorLogPath" -ForegroundColor Yellow
        } catch {
            # Ignore logging errors
        }
        
        throw
    }
}

#endregion Main Installation Logic

# Execute main installation
try {
    Install-OpksshServer
}
catch {
    # Final catch to improve error display.
    $_.Exception | Write-Host -ForegroundColor Red
}
