#!/usr/bin/env node
/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Builds a redistributable "DiscordPG build of Vencord" and zips it with the
 * install scripts. The bundle is platform-independent: Vencord is built with
 * --standalone (no process.platform baked in) and --disable-updater (so Vencord's
 * self-updater cannot replace the bundle with a plugin-less upstream build).
 *
 *   node scripts/package.mjs [--vencord <dir>] [--sign <fingerprint>] [--no-build]
 */

import { execFileSync, spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "..");
const args = process.argv.slice(2);
const opt = (name, dflt = null) => { const i = args.indexOf(name); return i === -1 ? dflt : args[i + 1]; };
const has = name => args.includes(name);

// Cloned into a Vencord tree (src/userplugins/discordPG.desktop) the checkout is three levels up;
// otherwise assume a sibling checkout that has this repo symlinked in.
const enclosing = join(repo, "..", "..", "..");
const defaultVencord = existsSync(join(enclosing, "scripts", "build", "build.mjs")) ? enclosing : join(repo, "..", "Vencord");
const vencordDir = resolve(opt("--vencord", process.env.VENCORD_DIR ?? defaultVencord));
const signWith = opt("--sign");
const pkg = JSON.parse(readFileSync(join(repo, "package.json"), "utf8"));

function die(msg) { console.error(`package: ${msg}`); process.exit(1); }
function run(cmd, cmdArgs, cwd) {
    const r = spawnSync(cmd, cmdArgs, { cwd, stdio: "inherit", env: process.env });
    if (r.status !== 0) die(`${cmd} ${cmdArgs.join(" ")} failed (exit ${r.status ?? r.signal})`);
}

// 1. Sanity: the Vencord checkout must contain THIS plugin as a userplugin.
if (!existsSync(join(vencordDir, "package.json"))) die(`no Vencord checkout at ${vencordDir} (pass --vencord <dir>)`);
const pluginDir = join(vencordDir, "src", "userplugins", "discordPG.desktop");
if (!existsSync(pluginDir)) die(`${pluginDir} does not exist; symlink or clone this repo there first`);
if (realpathSync(pluginDir) !== realpathSync(repo)) console.warn(`package: warning: ${pluginDir} is not this checkout (${realpathSync(pluginDir)})`);

const vencordHash = execFileSync("git", ["rev-parse", "--short", "HEAD"], { cwd: vencordDir, encoding: "utf8" }).trim();
const vencordDirty = execFileSync("git", ["status", "--porcelain", "--untracked-files=no"], { cwd: vencordDir, encoding: "utf8" }).trim() !== "";
let pluginHash = "unversioned";
try { pluginHash = execFileSync("git", ["rev-parse", "--short", "HEAD"], { cwd: repo, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim(); } catch { /* not committed yet */ }

// 2. Build Vencord: universal + updater off.
if (!has("--no-build")) {
    console.log(`package: building Vencord ${vencordHash}${vencordDirty ? " (dirty)" : ""} with --standalone --disable-updater`);
    run("pnpm", ["build", "--standalone", "--disable-updater"], vencordDir);
}
const dist = join(vencordDir, "dist");
const renderer = readFileSync(join(dist, "renderer.js"), "utf8");
if (!renderer.includes("Standalone: true") || !renderer.includes("Updater Disabled: true")) die("dist/renderer.js was not built with --standalone --disable-updater");
if (!/name:"DiscordPG"/.test(renderer)) die("dist/renderer.js does not contain the DiscordPG plugin");
const patcher = readFileSync(join(dist, "patcher.js"), "utf8");
// IPC channel names are built at runtime, so look for strings only DiscordPG's native code contains.
if (!patcher.includes("reloadagent") || !patcher.includes("--trust-model")) die("dist/patcher.js does not contain DiscordPG's native side");

// 3. Assemble the bundle.
const name = `DiscordPG-${pkg.version}-vencord-${vencordHash}`;
const outRoot = join(repo, "release");
const bundle = join(outRoot, name);
rmSync(bundle, { recursive: true, force: true });
mkdirSync(join(bundle, "dist"), { recursive: true });

const FILES = [
    "patcher.js", "preload.js", "renderer.js", "renderer.css",
    "vencordDesktopMain.js", "vencordDesktopPreload.js", "vencordDesktopRenderer.js", "vencordDesktopRenderer.css",
    "patcher.js.LEGAL.txt", "renderer.js.LEGAL.txt", "vencordDesktopMain.js.LEGAL.txt", "vencordDesktopRenderer.js.LEGAL.txt",
];
for (const f of FILES) {
    const src = join(dist, f);
    if (!existsSync(src)) { if (f.endsWith(".LEGAL.txt")) continue; die(`missing ${src}`); }
    copyFileSync(src, join(bundle, "dist", f));
}
for (const f of ["install.ps1", "install.sh", "INSTALL.md"]) copyFileSync(join(here, "bundle", f), join(bundle, f));
copyFileSync(join(repo, "LICENSE"), join(bundle, "LICENSE"));
writeFileSync(join(bundle, "VERSION.json"), JSON.stringify({
    discordpg: pkg.version, discordpgCommit: pluginHash, vencordCommit: vencordHash, vencordDirty,
    builtAt: new Date().toISOString(), builtOn: process.platform, node: process.version,
}, null, 2) + "\n");

// 4. Zip it (python's zipfile is everywhere; `zip` is not).
const zipPath = join(outRoot, `${name}.zip`);
rmSync(zipPath, { force: true });
// Zip the bundle's *contents* at the archive root: Windows Explorer's "Extract All" already creates a
// folder named after the zip, so a top-level folder inside would double-nest it.
const entries = readdirSync(bundle);
const py = spawnSync("python3", ["-m", "zipfile", "-c", zipPath, ...entries], { cwd: bundle, stdio: "inherit" });
if (py.status !== 0) {
    run("zip", ["-qr", zipPath, ...entries], bundle);
}
console.log(`package: wrote ${zipPath} (${(statSync(zipPath).size / 1024 / 1024).toFixed(1)} MiB)`);

// 5. Optional detached signature so testers can verify the bundle came from you.
if (signWith) {
    run("gpg", ["--batch", "--yes", "--armor", "--detach-sign", "--local-user", signWith, "--output", `${zipPath}.asc`, zipPath]);
    console.log(`package: signed -> ${zipPath}.asc`);
} else {
    console.log(`package: tip: sign it with  gpg --armor --detach-sign ${zipPath}`);
}
