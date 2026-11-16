#Requires -Version 5.1
<#
.SYNOPSIS
  Installs the DiscordPG build of Vencord into Discord on Windows.
.DESCRIPTION
  Copies the bundled Vencord files (which include the DiscordPG plugin) to
  %APPDATA%\DiscordPG\dist, downloads the official Vencord command-line
  installer from GitHub, and runs it in "dev install" mode so Discord loads
  these files instead of a download from Vencord's release server.

  This is a complete Vencord build: it replaces the Vencord build Discord currently loads. If you
  already use Vencord the script explains what changes and asks first; -Yes skips the question.

  Run from the folder you unzipped:   powershell -ExecutionPolicy Bypass -File .\install.ps1
  Options: -Branch stable|ptb|canary (default stable)   -Location <path to Discord>   -Yes   -Uninstall
#>
param(
    [ValidateSet("auto", "stable", "ptb", "canary")] [string] $Branch = "stable",
    [string] $Location = "",
    [switch] $Yes,
    [switch] $Uninstall
)
$ErrorActionPreference = "Stop"

$Root   = Split-Path -Parent $MyInvocation.MyCommand.Path
$Target = Join-Path $env:APPDATA "DiscordPG"
$Cli    = Join-Path $Target "VencordInstallerCli.exe"
$CliUrl = "https://github.com/Vencord/Installer/releases/latest/download/VencordInstallerCli.exe"

if (-not (Test-Path (Join-Path $Root "dist\patcher.js")) -and -not $Uninstall) {
    throw "dist\patcher.js not found next to this script. Unzip the whole bundle first."
}

# Someone who already runs Vencord (settings exist) and has not installed this bundle before is about to
# have their Vencord build swapped out. Say so and let them back out before anything is touched.
$VencordData = Join-Path $env:APPDATA "Vencord"   # Vencord's own settings folder, shared by every Vencord build
$hasVencord  = Test-Path (Join-Path $VencordData "settings\settings.json")
$hadBundle   = Test-Path (Join-Path $Target "VERSION.json")
if (-not $Uninstall -and -not $Yes -and $hasVencord -and -not $hadBundle) {
    Write-Host "You already use Vencord on this computer ($VencordData)." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "This bundle is a complete Vencord build with DiscordPG compiled in. Installing it makes Discord load"
    Write-Host "this build INSTEAD of the Vencord you have now:"
    Write-Host "  * your Vencord settings and enabled plugins are kept;"
    Write-Host "  * plugins you added yourself (src\userplugins) are NOT part of this build;"
    Write-Host "  * Vencord's updater is off in this build; you update by installing a newer bundle."
    Write-Host ""
    Write-Host "If you build Vencord from source, add DiscordPG to your own checkout instead and keep everything:"
    Write-Host "  see 'Add DiscordPG to your Vencord' in the README of the DiscordPG repository."
    Write-Host "You can go back at any time by running the official Vencord installer (or pnpm inject in your checkout)."
    Write-Host ""
    $answer = Read-Host "Replace your current Vencord build with this one? [y/N]"
    if ($answer -notmatch '^[Yy]') { Write-Host "Nothing was changed."; exit 0 }
}

# Discord keeps app.asar open while running, so the patcher cannot rename it.
$running = Get-Process -Name "Discord", "DiscordPTB", "DiscordCanary" -ErrorAction SilentlyContinue
if ($running) {
    Write-Host "Discord is running. It must be closed to patch it." -ForegroundColor Yellow
    $answer = Read-Host "Close Discord now? [y/N]"
    if ($answer -match '^[Yy]') { $running | Stop-Process -Force; Start-Sleep -Seconds 2 } else { throw "Close Discord and run this script again." }
}

New-Item -ItemType Directory -Force -Path $Target | Out-Null
if (-not $Uninstall) {
    Write-Host "Copying Vencord+DiscordPG files to $Target\dist"
    $distTarget = Join-Path $Target "dist"
    if (Test-Path $distTarget) { Remove-Item -Recurse -Force $distTarget }
    Copy-Item -Recurse -Force (Join-Path $Root "dist") $distTarget
    Copy-Item -Force (Join-Path $Root "VERSION.json") $Target -ErrorAction SilentlyContinue
}

Write-Host "Downloading the Vencord installer ($CliUrl)"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $CliUrl -OutFile $Cli -UseBasicParsing

# Dev-install mode: the installer skips downloading Vencord and points Discord at $Target\dist\patcher.js.
$env:VENCORD_USER_DATA_DIR = $Target
$env:VENCORD_DEV_INSTALL   = "1"

$cliArgs = @()
if ($Uninstall) { $cliArgs += "-uninstall" } else { $cliArgs += "-install" }
if ($Location -ne "") { $cliArgs += @("-location", $Location) } else { $cliArgs += @("-branch", $Branch) }

Write-Host "Running: VencordInstallerCli.exe $($cliArgs -join ' ')"
# The installer logs to stderr. Under $ErrorActionPreference = "Stop", Windows PowerShell 5.1 would turn
# the first such line into a NativeCommandError, so run it as a separate process and use the exit code.
$quoted = $cliArgs | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }
$proc = Start-Process -FilePath $Cli -ArgumentList ($quoted -join ' ') -NoNewWindow -Wait -PassThru
if ($proc.ExitCode -ne 0) { throw "The Vencord installer exited with code $($proc.ExitCode). Read its output above." }

if ($Uninstall) {
    Write-Host "Vencord/DiscordPG removed from Discord. (Settings and bindings in %APPDATA%\Vencord were left in place.)" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "Done. Start Discord, open Settings > Vencord > Plugins and check that DiscordPG is enabled," -ForegroundColor Green
    Write-Host "then pick your key at the top of the DiscordPG settings page. See INSTALL.md for the GnuPG setup." -ForegroundColor Green
    Write-Host "Re-run this script after Discord updates itself (the patch lives inside the app-<version> folder)."
}
