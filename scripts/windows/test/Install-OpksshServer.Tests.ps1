# Requires -Version 5.1

BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot "..\Install-OpksshServer.ps1"
    . $scriptPath
}

Describe "Set-SshdConfiguration" {
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
        $final | Should -Match [regex]::Escape("AuthorizedKeysCommand $quotedBinary verify %u %k %t")
        $final | Should -Match [regex]::Escape("AuthorizedKeysCommandUser $authUser")
    }

    It "returns false when a different AuthorizedKeysCommand is present and overwrite is not set" {
        $tempPath = Join-Path $env:TEMP "sshd_config.test.$([guid]::NewGuid().ToString())"
        @(
            "AuthorizedKeysCommand \"C:\\Other\\opkssh.exe\" verify %u %k %t",
            "AuthorizedKeysCommandUser otheruser"
        ) | Set-Content -Path $tempPath -Force

        $result = Set-SshdConfiguration -BinaryPath "C:\Program Files\opkssh\opkssh.exe" -AuthCmdUser "opksshuser" -SshdConfigPath $tempPath
        $result | Should -BeFalse
    }

    It "overwrites existing configuration when -OverwriteConfig is set" {
        $tempPath = Join-Path $env:TEMP "sshd_config.test.$([guid]::NewGuid().ToString())"
        @(
            "AuthorizedKeysCommand \"C:\\Other\\opkssh.exe\" verify %u %k %t",
            "AuthorizedKeysCommandUser otheruser"
        ) | Set-Content -Path $tempPath -Force

        $binaryPath = "C:\Program Files\opkssh\opkssh.exe"
        $authUser = "opksshuser"
        $quotedBinary = "`"$binaryPath`""

        $result = Set-SshdConfiguration -BinaryPath $binaryPath -AuthCmdUser $authUser -OverwriteConfig $true -SshdConfigPath $tempPath
        $result | Should -BeTrue

        $final = Get-Content -Path $tempPath -Raw
        $final | Should -Match [regex]::Escape("AuthorizedKeysCommand $quotedBinary verify %u %k %t")
        $final | Should -Match [regex]::Escape("AuthorizedKeysCommandUser $authUser")
    }
}