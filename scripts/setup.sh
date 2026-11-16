#!/usr/bin/env bash
# DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
# Copyright (c) 2026 DiscordPG contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Adds DiscordPG to a Vencord source checkout, builds that checkout and injects it into Discord.
# Vencord compiles plugins in at build time, so this is the only way to add a plugin to it.
#
#   scripts/setup.sh [--vencord <dir>] [--branch stable|ptb|canary] [--location <discord dir>]
#                    [--no-inject] [--yes]
#
# The script only ever adds the folder src/userplugins/discordPG.desktop to the checkout. It never
# pulls, resets or edits Vencord itself, and it leaves your other userplugins alone.
# See the Install section of README.md for the same steps done by hand.
set -euo pipefail

PLUGIN_DIRNAME="discordPG.desktop"   # the ".desktop" suffix matters: it keeps the plugin out of web builds
VENCORD_URL="https://github.com/Vendicated/Vencord"

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

vencord=""; branch=""; location=""; inject=1; assume_yes=0
while [ $# -gt 0 ]; do
    case "$1" in
        --vencord) vencord="${2:?--vencord needs a directory}"; shift 2 ;;
        --branch) branch="${2:?--branch needs stable, ptb or canary}"; shift 2 ;;
        --location) location="${2:?--location needs a directory}"; shift 2 ;;
        --no-inject) inject=0; shift ;;
        --yes|-y) assume_yes=1; shift ;;
        -h|--help) sed -n '6,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $1 (try --help)" >&2; exit 1 ;;
    esac
done

say() { printf '\n==> %s\n' "$*"; }
die() { printf 'setup: %s\n' "$*" >&2; exit 1; }
confirm() {
    [ "$assume_yes" = 1 ] && return 0
    [ -t 0 ] || die "$1 Re-run with --yes to accept."
    local answer; read -r -p "$1 [y/N] " answer
    case "$answer" in [Yy]*) return 0 ;; *) return 1 ;; esac
}

# 1. Tools.
command -v git >/dev/null 2>&1 || die "git is not installed."
command -v node >/dev/null 2>&1 || die "Node.js is not installed (Vencord needs v18 or newer): https://nodejs.org/"
node_major="$(node -p 'process.versions.node.split(".")[0]')"
[ "$node_major" -ge 18 ] || die "Node.js $(node -v) is too old; Vencord needs v18 or newer."
command -v pnpm >/dev/null 2>&1 || die "pnpm is not installed. Run 'corepack enable' (ships with Node.js) or 'npm install -g pnpm', then try again."

tested="$(node -p 'require(process.argv[1]).testedWith?.vencord ?? "unknown"' "$repo/package.json" 2>/dev/null || echo unknown)"

# 2. Find the Vencord checkout.
is_checkout() { [ -f "$1/package.json" ] && [ -f "$1/scripts/build/build.mjs" ] && [ -d "$1/src" ]; }

in_tree=0
parent="$(dirname "$repo")"
if [ "$(basename "$parent")" = "userplugins" ] && is_checkout "$parent/../.."; then
    in_tree=1
    found="$(cd "$parent/../.." && pwd -P)"
    if [ -n "$vencord" ] && [ "$(cd "$vencord" 2>/dev/null && pwd -P)" != "$found" ]; then
        die "this copy of DiscordPG already sits inside $found; drop --vencord or run the script from another clone."
    fi
    vencord="$found"
    say "Using the Vencord checkout this plugin is already in: $vencord"
else
    [ -n "$vencord" ] || vencord="$HOME/Vencord"
    if ! is_checkout "$vencord"; then
        if [ -e "$vencord" ] && [ -n "$(ls -A "$vencord" 2>/dev/null)" ]; then
            die "$vencord exists but is not a Vencord source checkout. Pass --vencord <dir>."
        fi
        confirm "No Vencord source checkout at $vencord. Clone $VENCORD_URL there?" || die "nothing done."
        say "Cloning Vencord into $vencord"
        git clone "$VENCORD_URL" "$vencord"
    fi
    vencord="$(cd "$vencord" && pwd -P)"
    say "Using Vencord checkout: $vencord"
fi

pkg_name="$(node -p 'require(process.argv[1]).name' "$vencord/package.json" 2>/dev/null || echo "?")"
if [ "$pkg_name" != "vencord" ]; then
    echo "setup: warning: $vencord is '$pkg_name', not Vencord. Forks are untested with DiscordPG; continuing anyway." >&2
fi

# 3. Put the plugin into src/userplugins (unless it is already there).
dest="$vencord/src/userplugins/$PLUGIN_DIRNAME"
if [ "$in_tree" = 0 ]; then
    if [ -e "$dest" ] || [ -L "$dest" ]; then
        if [ "$(cd "$dest" 2>/dev/null && pwd -P)" = "$repo" ]; then
            say "$dest already points at this checkout."
        else
            at="$(git -C "$dest" rev-parse --short HEAD 2>/dev/null || echo "not a git checkout")"
            say "DiscordPG is already present at $dest ($at). Leaving it as it is."
            echo "    To update it:  git -C \"$dest\" pull"
        fi
    else
        mkdir -p "$vencord/src/userplugins"
        if [ -d "$repo/.git" ]; then
            if [ -n "$(git -C "$repo" status --porcelain 2>/dev/null)" ]; then
                echo "setup: note: uncommitted changes in $repo are not carried over (the commit $(git -C "$repo" rev-parse --short HEAD) is cloned)." >&2
            fi
            say "Cloning DiscordPG into $dest"
            git clone -q "$repo" "$dest"
            origin="$(git -C "$repo" remote get-url origin 2>/dev/null || true)"
            if [ -n "$origin" ]; then git -C "$dest" remote set-url origin "$origin"; else git -C "$dest" remote remove origin; fi
        else
            say "Copying DiscordPG into $dest"
            mkdir "$dest"
            tar -C "$repo" --exclude=./node_modules --exclude=./release -cf - . | tar -C "$dest" -xf -
        fi
        echo "    DiscordPG now lives at $dest. Update it there; this folder ($repo) is no longer needed."
    fi
fi

# 4. Build the whole checkout (Vencord, your other userplugins, DiscordPG).
say "Installing Vencord's dependencies and building"
if ! (cd "$vencord" && pnpm install --frozen-lockfile && pnpm build); then
    cat >&2 <<EOF

setup: the Vencord build failed.
  Vencord builds itself and every plugin in src/userplugins together, so the error above may come from
  another plugin or from a Vencord checkout that is too old (esbuild names the file it stopped at).
  DiscordPG was tested with Vencord $tested. Nothing was changed in Discord.
EOF
    exit 1
fi

renderer="$vencord/dist/renderer.js"; patcher="$vencord/dist/patcher.js"
grep -q 'name:"DiscordPG"' "$renderer" 2>/dev/null || die "the build finished but dist/renderer.js does not contain DiscordPG. Is the folder named $PLUGIN_DIRNAME?"
{ grep -q 'reloadagent' "$patcher" && grep -q -- '--trust-model' "$patcher"; } 2>/dev/null || die "the build finished but dist/patcher.js does not contain DiscordPG's native half."
say "Build OK: DiscordPG is compiled into $vencord/dist"

# 5. Point Discord at this build.
if [ "$inject" = 0 ]; then
    echo "Skipping injection (--no-inject). When you are ready:  cd \"$vencord\" && pnpm inject"
    exit 0
fi
if pgrep -f '[Dd]iscord' >/dev/null 2>&1; then
    echo "setup: Discord appears to be running. Quit it fully (tray icon > Quit) before the next step." >&2
    confirm "Continue with the injection?" || { echo "Stopped before injecting. Later:  cd \"$vencord\" && pnpm inject"; exit 0; }
fi
say "Running Vencord's installer (it points Discord at $vencord/dist; your Vencord settings are kept)"
args=(--install)
[ -n "$location" ] && args+=(-location "$location")
[ -n "$branch" ] && args+=(-branch "$branch")
if [ -f "$vencord/scripts/runInstaller.mjs" ]; then
    (cd "$vencord" && node scripts/runInstaller.mjs -- "${args[@]}")
else
    (cd "$vencord" && pnpm inject)   # a fork with its own injector
fi

cat <<EOF

Done. Start Discord, open Settings > Vencord > Plugins > DiscordPG and pick your key at the top of its
settings page.
  * Updating DiscordPG:  git -C "$dest" pull && (cd "$vencord" && pnpm build), then fully restart Discord.
  * After Discord updates itself the patch is gone:  cd "$vencord" && pnpm inject
  * Removing DiscordPG:  delete $dest and run pnpm build again.
EOF
