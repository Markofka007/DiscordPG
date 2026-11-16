/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Spawning gpg safely from the Electron main process. Plain Node; no Electron
 * imports so this module is unit-testable.
 */

import { execFile, spawn } from "child_process";
import { access, constants, stat } from "fs/promises";
import { basename, dirname, isAbsolute, join } from "path";

import { DECRYPT_MAX_OUTPUT_BYTES } from "../core/types";
import { RunOutcome } from "./status";

/** Flags applied to every invocation. See the "Security principles" section of the plan. */
export const HARDENING_FLAGS = [
    "--batch",
    "--no-tty",
    "--status-fd", "2",
    "--exit-on-status-write-error",
    "--no-auto-key-retrieve",
    "--no-auto-key-locate",
    "--disable-dirmngr",
    "--no-greeting",
    "--quiet",
    "--utf8-strings",
    "--display-charset", "utf-8",
];

const GPG_BASENAMES = new Set(["gpg", "gpg2", "gpg.exe", "gpg2.exe"]);
const IS_WIN = process.platform === "win32";

/**
 * Directories we trust to hold a gpg binary on Windows. Node's fs.access(W_OK)
 * only looks at the read-only attribute there, not at ACLs, so instead of
 * "directory not writable" we require the binary to sit under a root that is
 * admin-protected by the default Windows ACLs.
 */
export function windowsProtectedRoots(env: NodeJS.ProcessEnv = process.env): string[] {
    const roots = [env.ProgramFiles, env["ProgramFiles(x86)"], env.ProgramW6432, env.SystemRoot]
        .filter((r): r is string => typeof r === "string" && r.length > 0);
    return [...new Set(roots.map(normalizeWin))];
}

/** Lower-case, backslash-separated, trailing backslash. Used for prefix comparison only. */
function normalizeWin(p: string): string {
    const n = p.replace(/\//g, "\\").replace(/\\+$/, "").toLowerCase();
    return n + "\\";
}

export function isUnderProtectedRoot(p: string, roots: string[]): boolean {
    const n = normalizeWin(p);
    return roots.some(r => n.startsWith(r));
}

/** Default Gpg4win / GnuPG installer locations. Resolved from the environment rather than hardcoding C:\. */
function wellKnownCandidates(): string[] {
    if (!IS_WIN) return ["/usr/bin/gpg", "/usr/local/bin/gpg", "/opt/homebrew/bin/gpg", "/usr/bin/gpg2"];
    const roots = [process.env["ProgramFiles(x86)"], process.env.ProgramFiles, process.env.ProgramW6432]
        .filter((r): r is string => !!r);
    return [...new Set(roots)].flatMap(r => [join(r, "GnuPG", "bin", "gpg.exe"), join(r, "Gpg4win", "..", "GnuPG", "bin", "gpg.exe")]);
}

const STDOUT_CAP = DECRYPT_MAX_OUTPUT_BYTES + 64 * 1024;
const STDERR_CAP = 1024 * 1024;

async function isExecutableFile(p: string): Promise<boolean> {
    try {
        const s = await stat(p);
        if (!s.isFile()) return false;
        await access(p, constants.X_OK); // no-op on Windows (behaves like F_OK), which is fine: the root check carries the weight there
        return true;
    } catch {
        return false;
    }
}

/**
 * Is this a path we are willing to execute? It must be absolute, be named like
 * gpg, exist, and live somewhere the *current user cannot write to*. The
 * renderer is untrusted, and without the last rule a hostile plugin could point
 * us at any script it dropped in $HOME and get main-process code execution.
 * POSIX: the parent directory must not be writable. Windows: the path must sit
 * under Program Files / the Windows directory (see windowsProtectedRoots).
 */
export async function isAcceptableGpgPath(p: string): Promise<{ ok: true } | { ok: false; reason: string }> {
    if (!isAbsolute(p)) return { ok: false, reason: "not an absolute path" };
    if (!GPG_BASENAMES.has(basename(p).toLowerCase())) return { ok: false, reason: "must be named gpg or gpg2" };
    if (!(await isExecutableFile(p))) return { ok: false, reason: "not an executable file" };
    if (IS_WIN) {
        if (!isUnderProtectedRoot(p, windowsProtectedRoots())) {
            return { ok: false, reason: "on Windows gpg must be installed under Program Files (Gpg4win / GnuPG installer); per-user installs such as scoop are refused" };
        }
        return { ok: true };
    }
    try {
        await access(dirname(p), constants.W_OK);
        return { ok: false, reason: "directory is writable by the current user; refusing to execute from there" };
    } catch {
        return { ok: true };
    }
}

/** gpgconf percent-escapes ':' (and other bytes) in its directory listing, e.g. "C%3a\\Program Files". */
export function decodeGpgconf(s: string): string {
    return s.replace(/%([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

function execText(file: string, args: string[]): Promise<string | null> {
    return new Promise(resolve => {
        execFile(file, args, { timeout: 5000, windowsHide: true }, (err, stdout) => resolve(err ? null : String(stdout)));
    });
}

async function gpgconfBindir(): Promise<string | null> {
    const names = IS_WIN ? ["gpgconf.exe", ...wellKnownCandidates().map(c => join(dirname(c), "gpgconf.exe"))] : ["gpgconf"];
    for (const name of names) {
        const out = await execText(name, ["--list-dirs", "bindir"]);
        const line = out?.split(/\r?\n/)[0]?.trim();
        if (line) return decodeGpgconf(line.replace(/^bindir:/, ""));
    }
    return null;
}

/** Gpg4win / the GnuPG installer record their install directory in the registry. Best effort. */
async function registryInstallDirs(): Promise<string[]> {
    if (!IS_WIN) return [];
    const out: string[] = [];
    for (const key of ["HKLM\\SOFTWARE\\GnuPG", "HKLM\\SOFTWARE\\WOW6432Node\\GnuPG"]) {
        const txt = await execText("reg.exe", ["query", key, "/v", "Install Directory"]);
        const m = txt && /Install Directory\s+REG_SZ\s+(.+?)\s*$/m.exec(txt);
        if (m) out.push(join(m[1].trim(), "bin", "gpg.exe"));
    }
    return out;
}

let resolved: { configured: string | null; path: string | null } | null = null;

/** Find gpg, preferring a user-configured path (validated), then gpgconf, then the registry, then well-known locations. */
export async function findGpg(configured: string | null | undefined): Promise<{ path: string | null; reason?: string }> {
    const cfg = configured?.trim() || null;
    if (resolved && resolved.configured === cfg && resolved.path) return { path: resolved.path };

    if (cfg) {
        const verdict = await isAcceptableGpgPath(cfg);
        if (!verdict.ok) return { path: null, reason: `configured gpg path rejected: ${verdict.reason}` };
        resolved = { configured: cfg, path: cfg };
        return { path: cfg };
    }

    const bindir = await gpgconfBindir();
    const candidates = [
        ...(bindir ? [join(bindir, IS_WIN ? "gpg.exe" : "gpg")] : []),
        ...(await registryInstallDirs()),
        ...wellKnownCandidates(),
    ];
    const rejected: string[] = [];
    for (const c of candidates) {
        const v = await isAcceptableGpgPath(c);
        if (v.ok) {
            resolved = { configured: null, path: c };
            return { path: c };
        }
        rejected.push(`${c}: ${v.reason}`);
    }
    return { path: null, reason: `gpg not found. Tried: ${rejected.join("; ") || "(no candidates)"}` };
}

export function resetGpgPathCache() { resolved = null; }

export interface RunOptions {
    gpgPath: string;
    args: string[];
    stdin?: string | Buffer;
    timeoutMs: number;
    /** Tests only: run against an isolated GNUPGHOME. Never reachable from IPC. */
    homedir?: string;
    stdoutCap?: number;
    /** Return stdout as bytes (attachments); the string form is left empty. */
    binaryStdout?: boolean;
}

/** Run one gpg process to completion, enforcing time and output caps. */
export function runGpgRaw(opts: RunOptions): Promise<RunOutcome> {
    return new Promise(resolve => {
        const args = [
            ...(opts.homedir ? ["--homedir", opts.homedir] : []),
            ...HARDENING_FLAGS,
            ...opts.args,
        ];
        const child = spawn(opts.gpgPath, args, {
            stdio: ["pipe", "pipe", "pipe"],
            env: process.env,
            windowsHide: true,
        });

        const out: Buffer[] = [];
        const err: Buffer[] = [];
        let outLen = 0;
        let errLen = 0;
        let timedOut = false;
        let overflowed = false;
        let settled = false;
        const stdoutCap = opts.stdoutCap ?? STDOUT_CAP;

        const kill = () => {
            try { child.kill("SIGTERM"); } catch { /* ignore */ }
            setTimeout(() => { try { child.kill("SIGKILL"); } catch { /* ignore */ } }, 2000).unref();
        };
        const timer = setTimeout(() => { timedOut = true; kill(); }, opts.timeoutMs);

        child.stdout.on("data", (b: Buffer) => {
            outLen += b.length;
            if (outLen > stdoutCap) { overflowed = true; kill(); return; }
            out.push(b);
        });
        child.stderr.on("data", (b: Buffer) => {
            errLen += b.length;
            if (errLen > STDERR_CAP) { overflowed = true; kill(); return; }
            err.push(b);
        });

        const finish = (exitCode: number | null, signal: NodeJS.Signals | null) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            const stdoutBytes = Buffer.concat(out);
            resolve({
                exitCode: overflowed ? null : exitCode,
                signal: overflowed ? "OVERFLOW" : signal,
                timedOut,
                stdout: opts.binaryStdout ? "" : stdoutBytes.toString("utf8"),
                stdoutBytes,
                stderr: Buffer.concat(err).toString("utf8"),
            });
        };
        child.on("error", e => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            resolve({ exitCode: null, signal: null, timedOut: false, stdout: "", stdoutBytes: Buffer.alloc(0), stderr: `[DiscordPG] spawn failed: ${(e as Error).message}` });
        });
        // Prefer "close" (all output flushed), but do not hang on it: a killed gpg
        // may leave a grandchild holding the pipes open. Finish shortly after "exit" regardless.
        child.on("close", finish);
        child.on("exit", (code, signal) => {
            setTimeout(() => finish(code, signal), 250).unref();
        });

        if (opts.stdin != null) {
            child.stdin.on("error", () => { /* EPIPE when gpg exits early; the close handler reports it */ });
            child.stdin.end(opts.stdin);
        } else {
            child.stdin.end();
        }
    });
}

/**
 * All gpg invocations go through one FIFO queue: smartcard operations do not
 * parallelise, pinentry prompts must not pile up, and it keeps the IPC surface
 * from being used to fork-bomb the agent.
 */
let tail: Promise<unknown> = Promise.resolve();
let queued = 0;
const MAX_QUEUE = 64;

export function enqueue<T>(fn: () => Promise<T>): Promise<T> {
    if (queued >= MAX_QUEUE) return Promise.reject(new Error("gpg queue is full"));
    queued++;
    const run = tail.then(fn, fn).finally(() => { queued--; });
    tail = run.catch(() => { /* keep the chain alive */ });
    return run;
}

export const runGpg = (opts: RunOptions) => enqueue(() => runGpgRaw(opts));

/** Ask gpg-agent to forget cached passphrases/PINs. Best effort. */
export function reloadAgent(gpgPath: string, homedir?: string): Promise<void> {
    const connect = join(dirname(gpgPath), IS_WIN ? "gpg-connect-agent.exe" : "gpg-connect-agent");
    return new Promise(resolve => {
        const args = [...(homedir ? ["--homedir", homedir] : []), "reloadagent", "/bye"];
        execFile(connect, args, { timeout: 5000, windowsHide: true }, () => resolve());
    });
}
