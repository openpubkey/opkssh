# Requires -Version 5.1

BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot "..\Install-OpksshServer.ps1"

    # Use AST parsing to extract only the functions we need for testing
    # without executing the script (which has #Requires -RunAsAdministrator)
    $scriptContent = Get-Content -Path $scriptPath -Raw

    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($scriptContent, [ref]$tokens, [ref]$errors)

    $functionsToLoad = @('Set-SshdConfiguration', 'Write-Log', 'Get-ProvidersTemplate', 'New-OpksshConfiguration')
    foreach ($funcName in $functionsToLoad) {
        $funcAst = $ast.Find(
            {
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq $funcName
            }.GetNewClosure(),
            $true
        )

        if (-not $funcAst) {
            throw "Could not find function '$funcName' in $scriptPath."
        }

        . ([scriptblock]::Create($funcAst.Extent.Text))
    }
}

Describe "Set-SshdConfiguration" {
    # Tests that Set-SshdConfiguration correctly detects, preserves, and
    # updates AuthorizedKeysCommand/AuthorizedKeysCommandUser in sshd_config.
    It "returns true when sshd_config already matches desired configuration" {
        $tempPath = Join-Path $env:TEMP "sshd_config.test.$([guid]::NewGuid().ToString())"
        $binaryPath = "C:\Program Files\opkssh\opkssh.exe"
        $authUser = "opksshuser"
        $quotedBinary = "`"$binaryPath`""

        @(
            "# Comment",
            "AuthorizedKeysCommand $quotedBinary verify %u %k %t",
            "AuthorizedKeysCommandUser $authUser"
        ) | Set-Content -Path $tempPath -Force

        $result = Set-SshdConfiguration -BinaryPath $binaryPath -AuthCmdUser $authUser -SshdConfigPath $tempPath
        $result | Should -BeTrue

        $final = Get-Content -Path $tempPath -Raw
        $final | Should -Match $([regex]::Escape("AuthorizedKeysCommand $quotedBinary verify %u %k %t"))
        $final | Should -Match $([regex]::Escape("AuthorizedKeysCommandUser $authUser"))
    }

    It "returns false when a different AuthorizedKeysCommand is present and overwrite is not set" {
        $tempPath = Join-Path $env:TEMP "sshd_config.test.$([guid]::NewGuid().ToString())"
        @(
            'AuthorizedKeysCommand "C:\Other\opkssh.exe" verify %u %k %t',
            'AuthorizedKeysCommandUser otheruser'
        ) | Set-Content -Path $tempPath -Force

        $result = Set-SshdConfiguration -BinaryPath "C:\Program Files\opkssh\opkssh.exe" -AuthCmdUser "opksshuser" -SshdConfigPath $tempPath
        $result | Should -BeFalse
    }

    It "overwrites existing configuration when -OverwriteConfig is set" {
        $tempPath = Join-Path $env:TEMP "sshd_config.test.$([guid]::NewGuid().ToString())"
        @(
            'AuthorizedKeysCommand "C:\Other\opkssh.exe" verify %u %k %t',
            'AuthorizedKeysCommandUser otheruser'
        ) | Set-Content -Path $tempPath -Force

        $binaryPath = "C:\Program Files\opkssh\opkssh.exe"
        $authUser = "opksshuser"
        $quotedBinary = "`"$binaryPath`""

        $result = Set-SshdConfiguration -BinaryPath $binaryPath -AuthCmdUser $authUser -OverwriteConfig $true -SshdConfigPath $tempPath
        $result | Should -BeTrue

        $final = Get-Content -Path $tempPath -Raw
        $final | Should -Match $([regex]::Escape("AuthorizedKeysCommand $quotedBinary verify %u %k %t"))
        $final | Should -Match $([regex]::Escape("AuthorizedKeysCommandUser $authUser"))
    }
}

Describe "New-OpksshConfiguration providers file" {
    # Tests that a new install writes the commented-out providers template,
    # or a providers file given with -ProvidersFrom, and never replaces
    # providers the administrator already configured.
    BeforeAll {
        # Lines opkssh reads as providers: comments and blank lines removed
        function Get-ActiveProviderLines([string]$Path) {
            @(Get-Content $Path | ForEach-Object { ($_ -replace '#.*', '').Trim() } | Where-Object { $_ })
        }
        # New-OpksshConfiguration grants this account access to the config directory
        $authUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    }

    BeforeEach {
        $configPath = Join-Path $env:TEMP "opk.test.$([guid]::NewGuid().ToString())"
        $providersPath = Join-Path $configPath "providers"
    }

    AfterEach {
        Remove-Item -Path $configPath -Recurse -Force -ErrorAction SilentlyContinue
    }

    It "writes a template that enables no provider" {
        New-OpksshConfiguration -ConfigPath $configPath -AuthCmdUser $authUser -WarningAction SilentlyContinue | Should -BeTrue

        $content = [System.IO.File]::ReadAllText($providersPath)
        $content | Should -Be (Get-ProvidersTemplate)
        $content | Should -Match ([regex]::Escape("# https://accounts.google.com <CLIENT-ID> 24h"))
        $content | Should -Not -Match "206584157355"
        $content | Should -Match "`r`n$"
        $content | Should -Not -Match "[^`r]`n"
        Get-ActiveProviderLines $providersPath | Should -HaveCount 0
    }

    It "lets a provider line be appended to the template" {
        # Same as the gha-windows workflow
        New-OpksshConfiguration -ConfigPath $configPath -AuthCmdUser $authUser -WarningAction SilentlyContinue | Out-Null
        Add-Content -Path $providersPath -Value 'https://token.actions.githubusercontent.com github oidc'

        Get-ActiveProviderLines $providersPath | Should -Be @('https://token.actions.githubusercontent.com github oidc')
    }

    It "writes the template when the providers file exists but is empty" {
        New-Item -ItemType Directory -Path $configPath -Force | Out-Null
        New-Item -ItemType File -Path $providersPath -Force | Out-Null

        New-OpksshConfiguration -ConfigPath $configPath -AuthCmdUser $authUser -WarningAction SilentlyContinue | Out-Null

        [System.IO.File]::ReadAllText($providersPath) | Should -Be (Get-ProvidersTemplate)
    }

    It "keeps a providers file that is not empty" {
        New-Item -ItemType Directory -Path $configPath -Force | Out-Null
        Set-Content -Path $providersPath -Value 'https://accounts.google.com my-client-id 24h'

        New-OpksshConfiguration -ConfigPath $configPath -AuthCmdUser $authUser | Out-Null

        Get-ActiveProviderLines $providersPath | Should -Be @('https://accounts.google.com my-client-id 24h')
    }

    It "writes the file given with -ProvidersFrom" {
        $providersFrom = Join-Path $env:TEMP "providers.test.$([guid]::NewGuid().ToString())"
        [System.IO.File]::WriteAllText($providersFrom, "# mine`r`nhttps://accounts.google.com my-client-id 24h`r`n")

        New-OpksshConfiguration -ConfigPath $configPath -AuthCmdUser $authUser -ProvidersFrom $providersFrom | Out-Null

        [System.IO.File]::ReadAllText($providersPath) | Should -Be ([System.IO.File]::ReadAllText($providersFrom))
        Remove-Item $providersFrom -Force
    }

    It "ends the file given with -ProvidersFrom with a newline" {
        $providersFrom = Join-Path $env:TEMP "providers.test.$([guid]::NewGuid().ToString())"
        [System.IO.File]::WriteAllText($providersFrom, "https://accounts.google.com my-client-id 24h")

        New-OpksshConfiguration -ConfigPath $configPath -AuthCmdUser $authUser -ProvidersFrom $providersFrom | Out-Null
        Add-Content -Path $providersPath -Value 'https://token.actions.githubusercontent.com github oidc'

        Get-ActiveProviderLines $providersPath | Should -Be @(
            'https://accounts.google.com my-client-id 24h',
            'https://token.actions.githubusercontent.com github oidc')
        Remove-Item $providersFrom -Force
    }

    It "does not use -ProvidersFrom when the providers file is not empty" {
        New-Item -ItemType Directory -Path $configPath -Force | Out-Null
        Set-Content -Path $providersPath -Value 'https://accounts.google.com existing-client-id 24h'
        $providersFrom = Join-Path $env:TEMP "providers.test.$([guid]::NewGuid().ToString())"
        Set-Content -Path $providersFrom -Value 'https://accounts.google.com new-client-id 24h'

        New-OpksshConfiguration -ConfigPath $configPath -AuthCmdUser $authUser -ProvidersFrom $providersFrom -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null

        Get-ActiveProviderLines $providersPath | Should -Be @('https://accounts.google.com existing-client-id 24h')
        ($warnings -join "`n") | Should -Match ([regex]::Escape("Not using $providersFrom"))
        Remove-Item $providersFrom -Force
    }
}
