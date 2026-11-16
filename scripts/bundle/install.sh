#!/usr/bin/env bash
# Installs the DiscordPG build of Vencord into Discord on Linux or macOS.
#   ./install.sh [--branch stable|ptb|canary] [--location /path/to/discord] [--yes] [--uninstall]
# This is a complete Vencord build: it replaces the Vencord build Discord currently loads (it asks first
# if you already use Vencord; --yes skips the question). See INSTALL.md. Requires curl.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
case "$(uname -s)" in
    Linux)  config="${XDG_CONFIG_HOME:-$HOME/.config}"; cli_name="VencordInstallerCli-linux" ;;
    Darwin) config="$HOME/Library/Application Support"; cli_name="VencordInstallerCli-darwin" ;;
    *) echo "unsupported OS: $(uname -s); use install.ps1 on Windows" >&2; exit 1 ;;
esac
target="$config/DiscordPG"
vencord_data="$config/Vencord"   # Vencord's own settings folder, shared by every Vencord build
cli="$target/$cli_name"
cli_url="https://github.com/Vencord/Installer/releases/latest/download/$cli_name"

branch="stable"; location=""; uninstall=0; assume_yes=0
while [ $# -gt 0 ]; do
    case "$1" in
        --branch) branch="$2"; shift 2 ;;
        --location) location="$2"; shift 2 ;;
        --uninstall) uninstall=1; shift ;;
        --yes|-y) assume_yes=1; shift ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done

if [ "$uninstall" = 0 ] && [ ! -f "$root/dist/patcher.js" ]; then
    echo "dist/patcher.js not found next to this script; unzip the whole bundle first" >&2; exit 1
fi
# Someone who already runs Vencord (settings exist) and has not installed this bundle before is about to
# have their Vencord build swapped out. Say so and let them back out before anything is touched.
if [ "$uninstall" = 0 ] && [ "$assume_yes" = 0 ] && [ -f "$vencord_data/settings/settings.json" ] && [ ! -f "$target/VERSION.json" ]; then
    cat <<NOTICE
You already use Vencord on this computer ($vencord_data).

This bundle is a complete Vencord build with DiscordPG compiled in. Installing it makes Discord load
this build INSTEAD of the Vencord you have now:
  * your Vencord settings and enabled plugins are kept;
  * plugins you added yourself (src/userplugins) are NOT part of this build;
  * Vencord's updater is off in this build; you update by installing a newer bundle.

If you build Vencord from source, add DiscordPG to your own checkout instead and keep everything:
  see "Add DiscordPG to your Vencord" in the README of the DiscordPG repository.
You can go back at any time by running the official Vencord installer (or pnpm inject in your checkout).

NOTICE
    if [ ! -t 0 ]; then echo "Not a terminal, so nothing was changed. Re-run with --yes to accept." >&2; exit 1; fi
    read -r -p "Replace your current Vencord build with this one? [y/N] " answer
    case "$answer" in [Yy]*) ;; *) echo "Nothing was changed."; exit 0 ;; esac
fi

if pgrep -f '[Dd]iscord' >/dev/null 2>&1; then
    echo "Discord appears to be running. Quit it first (the patch is loaded at startup)." >&2
fi

mkdir -p "$target"
if [ "$uninstall" = 0 ]; then
    echo "Copying Vencord+DiscordPG files to $target/dist"
    rm -rf "$target/dist"
    cp -R "$root/dist" "$target/dist"
    cp -f "$root/VERSION.json" "$target/" 2>/dev/null || true
fi

echo "Downloading the Vencord installer ($cli_url)"
curl -fsSL "$cli_url" -o "$cli"
chmod +x "$cli"

# Dev-install mode: the installer skips downloading Vencord and points Discord at $target/dist/patcher.js.
export VENCORD_USER_DATA_DIR="$target" VENCORD_DEV_INSTALL=1
args=()
if [ "$uninstall" = 1 ]; then args+=(-uninstall); else args+=(-install); fi
if [ -n "$location" ]; then args+=(-location "$location"); else args+=(-branch "$branch"); fi

echo "Running: $cli_name ${args[*]}"
# System-wide Discord installs (e.g. /opt/discord) need root to patch; the installer says so if it does.
"$cli" "${args[@]}"

if [ "$uninstall" = 1 ]; then
    echo "Vencord/DiscordPG removed from Discord. Settings and bindings in ~/.config/Vencord were left in place."
else
    echo
    echo "Done. Start Discord, open Settings > Vencord > Plugins and check that DiscordPG is enabled,"
    echo "then pick your key at the top of the DiscordPG settings page. See INSTALL.md for the GnuPG setup."
    echo "Re-run this script after Discord updates itself (the patch lives inside the app-<version> folder)."
fi
