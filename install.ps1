# easylock installer for Windows (PowerShell 5+).
#
#   irm https://raw.githubusercontent.com/zlixas/easylock/main/install.ps1 | iex
#
# Downloads the Windows release, checks it against SHA256SUMS, installs easylock.exe
# into %LOCALAPPDATA%\easylock\bin and adds that folder to the user PATH.
# Set $env:EASYLOCK_VERSION = "v0.2.0" to pin a version.

$ErrorActionPreference = "Stop"
$repo = "zlixas/easylock"
$version = if ($env:EASYLOCK_VERSION) { $env:EASYLOCK_VERSION } else { "latest" }
$asset = "easylock-x86_64-pc-windows-msvc.zip"
$base = if ($version -eq "latest") { "https://github.com/$repo/releases/latest/download" }
        else { "https://github.com/$repo/releases/download/$version" }
$installDir = Join-Path $env:LOCALAPPDATA "easylock\bin"

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("easylock-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Host "easylock-install: downloading $asset ($version)"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -UseBasicParsing "$base/$asset" -OutFile (Join-Path $tmp $asset)
    Invoke-WebRequest -UseBasicParsing "$base/SHA256SUMS" -OutFile (Join-Path $tmp "SHA256SUMS")

    $line = Get-Content (Join-Path $tmp "SHA256SUMS") | Where-Object { $_ -match "  $([regex]::Escape($asset))$" }
    if (-not $line) { throw "$asset is not listed in SHA256SUMS" }
    $expected = ($line -split "\s+")[0].ToLower()
    $actual = (Get-FileHash -Algorithm SHA256 (Join-Path $tmp $asset)).Hash.ToLower()
    if ($expected -ne $actual) { throw "checksum mismatch for $asset (expected $expected, got $actual)" }
    Write-Host "easylock-install: checksum OK"

    Expand-Archive -Path (Join-Path $tmp $asset) -DestinationPath $tmp -Force
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    Copy-Item (Join-Path $tmp "easylock-x86_64-pc-windows-msvc\easylock.exe") $installDir -Force

    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (($userPath -split ";") -notcontains $installDir) {
        [Environment]::SetEnvironmentVariable("Path", "$userPath;$installDir", "User")
        Write-Host "easylock-install: added $installDir to your PATH (open a new terminal)"
    }
    & (Join-Path $installDir "easylock.exe") --version
    Write-Host "easylock-install: done. Try:  easylock tui"
}
finally {
    Remove-Item -Recurse -Force $tmp
}
