<#
.SYNOPSIS
    Builds and packages the FETİH Windows distribution installer.

.DESCRIPTION
    1. Publishes the Fetih.Desktop WinUI 3 application in Release mode.
    2. Copies the CLI launcher batch and required assets into the publish directory.
    3. Invokes Inno Setup Compiler (ISCC) to build the standalone setup exe.

.PARAMETER Configuration
    Build configuration (Debug or Release). Default is Release.

.PARAMETER Runtime
    Target runtime identifier. Default is win-x64.

.PARAMETER Version
    Installer package version. Default is 0.1.0.

.PARAMETER InnoSetupPath
    Explicit path to ISCC.exe (Inno Setup Compiler).

.PARAMETER SkipPublish
    If specified, skips the dotnet publish step and only builds the installer from existing dist files.
#>

[CmdletBinding()]
param(
    [string]$Configuration = "Release",
    [string]$Runtime = "win-x64",
    [string]$Version = "0.1.0",
    [string]$InnoSetupPath = "",
    [switch]$SkipPublish
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..") | Select-Object -ExpandProperty Path
$ProjectPath = Join-Path $RepoRoot "apps\windows\Fetih.Desktop\Fetih.Desktop.csproj"
$PublishDir = Join-Path $RepoRoot "dist\$Runtime"
$OutputDir = Join-Path $RepoRoot "dist\installer"
$IssFile = Join-Path $ScriptDir "installer.iss"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  FETIH Windows Package & Installer Builder" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Configuration : $Configuration"
Write-Host "  Runtime       : $Runtime"
Write-Host "  Version       : $Version"
Write-Host "  Repo Root     : $RepoRoot"
Write-Host "  Publish Dir   : $PublishDir"
Write-Host "  Output Dir    : $OutputDir"
Write-Host ""

# 1. Publish WinUI 3 Desktop App
if (-not $SkipPublish) {
    Write-Host "[1/3] Publishing Fetih.Desktop..." -ForegroundColor Yellow
    
    if (-not (Test-Path $ProjectPath)) {
        throw "Project file not found at: $ProjectPath"
    }

    if (-not (Test-Path $PublishDir)) {
        New-Item -ItemType Directory -Path $PublishDir -Force | Out-Null
    }

    & dotnet publish $ProjectPath -c $Configuration -r $Runtime --no-self-contained -o $PublishDir
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet publish failed with exit code $LASTEXITCODE"
    }
    Write-Host "  [OK] WinUI 3 binaries published successfully." -ForegroundColor Green
} else {
    Write-Host "[1/3] Skipping publish step as requested." -ForegroundColor Gray
}

# 2. Stage CLI Launcher
Write-Host "[2/3] Staging CLI launcher and packaging assets..." -ForegroundColor Yellow
$FetihCmdSrc = Join-Path $ScriptDir "fetih.cmd"
$FetihCmdDst = Join-Path $PublishDir "fetih.cmd"
Copy-Item $FetihCmdSrc -Destination $FetihCmdDst -Force
Write-Host "  [OK] Staged fetih.cmd -> $FetihCmdDst" -ForegroundColor Green

# 3. Locate Inno Setup Compiler and build installer
Write-Host "[3/3] Locating Inno Setup Compiler..." -ForegroundColor Yellow

$IsccCandidates = @(
    $InnoSetupPath,
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    "C:\Program Files\Inno Setup 6\ISCC.exe",
    "C:\Program Files (x86)\Inno Setup 5\ISCC.exe"
)

$IsccExe = $null
foreach ($cand in $IsccCandidates) {
    if (![string]::IsNullOrEmpty($cand) -and (Test-Path $cand)) {
        $IsccExe = $cand
        break
    }
}

if (-not $IsccExe) {
    $cmd = Get-Command "iscc.exe" -ErrorAction SilentlyContinue
    if ($cmd) {
        $IsccExe = $cmd.Source
    }
}

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

if ($IsccExe) {
    Write-Host "  Found Inno Setup at: $IsccExe" -ForegroundColor Cyan
    Write-Host "  Compiling installer package..." -ForegroundColor Yellow

    $isccArgs = @(
        "/DAppVersion=$Version",
        "/DPublishDir=$PublishDir",
        "/DRepoRoot=$RepoRoot",
        "/DOutputDir=$OutputDir",
        $IssFile
    )

    & $IsccExe @isccArgs
    if ($LASTEXITCODE -ne 0) {
        throw "ISCC failed with exit code $LASTEXITCODE"
    }

    $InstallerExe = Join-Path $OutputDir "Fetih-Setup-$Version-$Runtime.exe"
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host "  SUCCESS: Installer created at:" -ForegroundColor Green
    Write-Host "  $InstallerExe" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "  [NOTICE] Inno Setup (ISCC.exe) was not found on this system." -ForegroundColor DarkYellow
    Write-Host "  Binaries and assets have been staged in: $PublishDir" -ForegroundColor Cyan
    Write-Host "  To generate the setup .exe, install Inno Setup 6 (https://jrsoftware.org/isdl.php)" -ForegroundColor Cyan
    Write-Host "  and run:" -ForegroundColor Cyan
    Write-Host "    & '$ScriptDir\build-installer.ps1' -SkipPublish" -ForegroundColor White
    Write-Host ""
}
