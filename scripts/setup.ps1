#Requires -Version 5.1
<#
.SYNOPSIS
  Adds DiscordPG to a Vencord source checkout, builds that checkout and injects it into Discord.
.DESCRIPTION
  Vencord compiles plugins in at build time, so this is the only way to add a plugin to it.

  The script only ever adds the folder src\userplugins\discordPG.desktop to the checkout. It never
  pulls, resets or edits Vencord itself, and it leaves your other userplugins alone.
  See the Install section of README.md for the same steps done by hand.

  Run:      powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1
  Options:  -Vencord <dir>   -Branch stable|ptb|canary   -Location <path to Discord>   -NoInject   -Yes
#>
# DiscordPG (Discord Privacy Guard) - Copyright (c) 2026 DiscordPG contributors
# SPDX-License-Identifier: GPL-3.0-or-later
param(
    [string] $Vencord = "",
    [ValidateSet("", "stable", "ptb", "canary")] [string] $Branch = "",
    [string] $Location = "",
    [switch] $NoInject,
    [switch] $Yes
)
$ErrorActionPreference = "Stop"

$PluginDirName = "discordPG.desktop"   # the ".desktop" suffix matters: it keeps the plugin out of web builds
$VencordUrl    = "https://github.com/Vendicated/Vencord"
$Repo          = (Resolve-Path (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "..")).Path

function Say([string] $Text) { Write-Host ""; Write-Host "==> $Text" -ForegroundColor Cyan }
function Confirm-Step([string] $Question) {
    if ($Yes) { return $true }
    return ((Read-Host "$Question [y/N]") -match '^[Yy]')
}
function Test-Checkout([string] $Dir) {
    return (Test-Path (Join-Path $Dir "package.json")) -and (Test-Path (Join-Path $Dir "scripts\build\build.mjs")) -and (Test-Path (Join-Path $Dir "src"))
}
# git, node and pnpm write progress to stderr. Under $ErrorActionPreference = "Stop", Windows PowerShell 5.1
# turns the first such line into a terminating error, so run them with "Continue" and use the exit code.
function Invoke-Tool([string] $WorkDir, [string] $Exe, [string[]] $Arguments) {
    Push-Location $WorkDir
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { & $Exe @Arguments | Out-Host; return $LASTEXITCODE }
    finally { $ErrorActionPreference = $previous; Pop-Location }
}
function Get-ToolOutput([string] $Exe, [string[]] $Arguments) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { $out = & $Exe @Arguments 2>$null; if ($LASTEXITCODE -ne 0) { return "" }; return ("$out").Trim() }
    finally { $ErrorActionPreference = $previous }
}

# 1. Tools.
foreach ($tool in "git", "node") {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { throw "$tool is not installed. Vencord needs Git and Node.js 18 or newer (https://nodejs.org/)." }
}
$nodeMajor = [int](Get-ToolOutput "node" @("-p", "process.versions.node.split('.')[0]"))
if ($nodeMajor -lt 18) { throw "Node.js is too old; Vencord needs v18 or newer." }
if (-not (Get-Command "pnpm" -ErrorAction SilentlyContinue)) {
    throw "pnpm is not installed. Run 'corepack enable' (ships with Node.js) or 'npm install -g pnpm', then try again."
}

$tested = "unknown"
try { $tested = (Get-Content -Raw (Join-Path $Repo "package.json") | ConvertFrom-Json).testedWith.vencord } catch { }

# 2. Find the Vencord checkout.
$inTree = $false
$parent = Split-Path -Parent $Repo
$candidate = Join-Path $parent "..\.."
if ((Split-Path -Leaf $parent) -eq "userplugins" -and (Test-Checkout $candidate)) {
    $inTree = $true
    $found = (Resolve-Path $candidate).Path
    if ($Vencord -ne "" -and (Test-Path $Vencord) -and ((Resolve-Path $Vencord).Path -ne $found)) {
        throw "This copy of DiscordPG already sits inside $found. Drop -Vencord or run the script from another clone."
    }
    $Vencord = $found
    Say "Using the Vencord checkout this plugin is already in: $Vencord"
} else {
    if ($Vencord -eq "") { $Vencord = Join-Path $env:USERPROFILE "Vencord" }
    if (-not (Test-Checkout $Vencord)) {
        if ((Test-Path $Vencord) -and (Get-ChildItem -Force $Vencord | Select-Object -First 1)) {
            throw "$Vencord exists but is not a Vencord source checkout. Pass -Vencord <dir>."
        }
        if (-not (Confirm-Step "No Vencord source checkout at $Vencord. Clone $VencordUrl there?")) { throw "Nothing done." }
        Say "Cloning Vencord into $Vencord"
        if ((Invoke-Tool $Repo "git" @("clone", $VencordUrl, $Vencord)) -ne 0) { throw "git clone failed." }
    }
    $Vencord = (Resolve-Path $Vencord).Path
    Say "Using Vencord checkout: $Vencord"
}

$pkgName = "?"
try { $pkgName = (Get-Content -Raw (Join-Path $Vencord "package.json") | ConvertFrom-Json).name } catch { }
if ($pkgName -ne "vencord") {
    Write-Host "Warning: $Vencord is '$pkgName', not Vencord. Forks are untested with DiscordPG; continuing anyway." -ForegroundColor Yellow
}

# 3. Put the plugin into src\userplugins (unless it is already there).
$userPlugins = Join-Path $Vencord "src\userplugins"
$dest = Join-Path $userPlugins $PluginDirName
if (-not $inTree) {
    if (Test-Path $dest) {
        $at = Get-ToolOutput "git" @("-C", $dest, "rev-parse", "--short", "HEAD")
        if ($at -eq "") { $at = "not a git checkout" }
        Say "DiscordPG is already present at $dest ($at). Leaving it as it is."
        Write-Host "    To update it:  git -C `"$dest`" pull"
    } else {
        New-Item -ItemType Directory -Force -Path $userPlugins | Out-Null
        if (Test-Path (Join-Path $Repo ".git")) {
            if ((Get-ToolOutput "git" @("-C", $Repo, "status", "--porcelain")) -ne "") {
                Write-Host "Note: uncommitted changes in $Repo are not carried over (the current commit is cloned)." -ForegroundColor Yellow
            }
            Say "Cloning DiscordPG into $dest"
            if ((Invoke-Tool $Repo "git" @("clone", "-q", $Repo, $dest)) -ne 0) { throw "git clone failed." }
            $origin = Get-ToolOutput "git" @("-C", $Repo, "remote", "get-url", "origin")
            if ($origin -ne "") { Invoke-Tool $dest "git" @("remote", "set-url", "origin", $origin) | Out-Null }
            else { Invoke-Tool $dest "git" @("remote", "remove", "origin") | Out-Null }
        } else {
            Say "Copying DiscordPG into $dest"
            New-Item -ItemType Directory -Path $dest | Out-Null
            Get-ChildItem -Force $Repo | Where-Object { $_.Name -notin "node_modules", "release" } |
                ForEach-Object { Copy-Item -Recurse -Force $_.FullName (Join-Path $dest $_.Name) }
        }
        Write-Host "    DiscordPG now lives at $dest. Update it there; this folder ($Repo) is no longer needed."
    }
}

# 4. Build the whole checkout (Vencord, your other userplugins, DiscordPG).
Say "Installing Vencord's dependencies and building"
$failed = (Invoke-Tool $Vencord "pnpm" @("install", "--frozen-lockfile")) -ne 0
if (-not $failed) { $failed = (Invoke-Tool $Vencord "pnpm" @("build")) -ne 0 }
if ($failed) {
    Write-Host ""
    Write-Host "The Vencord build failed." -ForegroundColor Red
    Write-Host "  Vencord builds itself and every plugin in src\userplugins together, so the error above may come from"
    Write-Host "  another plugin or from a Vencord checkout that is too old (esbuild names the file it stopped at)."
    Write-Host "  DiscordPG was tested with Vencord $tested. Nothing was changed in Discord."
    exit 1
}

$renderer = Join-Path $Vencord "dist\renderer.js"
$patcher  = Join-Path $Vencord "dist\patcher.js"
if (-not (Select-String -Path $renderer -SimpleMatch 'name:"DiscordPG"' -Quiet)) {
    throw "The build finished but dist\renderer.js does not contain DiscordPG. Is the folder named $PluginDirName?"
}
if (-not ((Select-String -Path $patcher -SimpleMatch 'reloadagent' -Quiet) -and (Select-String -Path $patcher -SimpleMatch '--trust-model' -Quiet))) {
    throw "The build finished but dist\patcher.js does not contain DiscordPG's native half."
}
Say "Build OK: DiscordPG is compiled into $Vencord\dist"

# 5. Point Discord at this build.
if ($NoInject) {
    Write-Host "Skipping injection (-NoInject). When you are ready:  cd `"$Vencord`"; pnpm inject"
    exit 0
}
# Discord keeps app.asar open while running, so the patcher cannot rename it.
$running = Get-Process -Name "Discord", "DiscordPTB", "DiscordCanary" -ErrorAction SilentlyContinue
if ($running) {
    Write-Host "Discord is running. It must be closed to patch it." -ForegroundColor Yellow
    if (Confirm-Step "Close Discord now?") { $running | Stop-Process -Force; Start-Sleep -Seconds 2 }
    else { Write-Host "Stopped before injecting. Later:  cd `"$Vencord`"; pnpm inject"; exit 0 }
}
Say "Running Vencord's installer (it points Discord at $Vencord\dist; your Vencord settings are kept)"
if (Test-Path (Join-Path $Vencord "scripts\runInstaller.mjs")) {
    $installerArgs = @("scripts/runInstaller.mjs", "--", "--install")
    if ($Location -ne "") { $installerArgs += @("-location", $Location) }
    if ($Branch -ne "") { $installerArgs += @("-branch", $Branch) }
    $code = Invoke-Tool $Vencord "node" $installerArgs
} else {
    $code = Invoke-Tool $Vencord "pnpm" @("inject")   # a fork with its own injector
}
if ($code -ne 0) { throw "The Vencord installer exited with code $code. Read its output above." }

Write-Host ""
Write-Host "Done. Start Discord, open Settings > Vencord > Plugins > DiscordPG and pick your key at the top of its" -ForegroundColor Green
Write-Host "settings page." -ForegroundColor Green
Write-Host "  * Updating DiscordPG:  git -C `"$dest`" pull; cd `"$Vencord`"; pnpm build   (then fully restart Discord)"
Write-Host "  * After Discord updates itself the patch is gone:  cd `"$Vencord`"; pnpm inject"
Write-Host "  * Removing DiscordPG:  delete $dest and run pnpm build again."
