/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * userId -> fingerprint bindings, persisted by the main process in a 0600 file.
 * The renderer can only change these through IPC calls that trigger a native
 * confirmation dialog (see confirm.ts), so a hostile renderer cannot silently
 * repoint a conversation at an attacker's key.
 */

import { mkdir, readFile, rename, writeFile } from "fs/promises";
import { dirname, join } from "path";

import { Binding, Fingerprint, FINGERPRINT_RE, Snowflake, SNOWFLAKE_RE } from "../core/types";

interface FileShape {
    version: 1;
    bindings: Record<Snowflake, Omit<Binding, "userId">>;
}

export class BindingStore {
    private data: FileShape = { version: 1, bindings: {} };
    private loaded = false;

    constructor(public readonly path: string) { }

    static defaultPath(dataDir: string) { return join(dataDir, "discordpg", "bindings.json"); }

    async load(): Promise<void> {
        if (this.loaded) return;
        this.loaded = true;
        let raw: string;
        try {
            raw = await readFile(this.path, "utf8");
        } catch {
            return; // first run
        }
        try {
            const parsed = JSON.parse(raw);
            this.data = sanitize(parsed);
        } catch {
            // Corrupt file: refuse to guess. Start empty but keep the corrupt file for the user to inspect.
            await rename(this.path, `${this.path}.corrupt-${Date.now()}`).catch(() => { });
            this.data = { version: 1, bindings: {} };
        }
    }

    private async save(): Promise<void> {
        await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
        const tmp = `${this.path}.tmp`;
        await writeFile(tmp, JSON.stringify(this.data, null, 2), { mode: 0o600 });
        await rename(tmp, this.path);
    }

    all(): Binding[] {
        return Object.entries(this.data.bindings).map(([userId, b]) => ({ userId, ...b }));
    }

    get(userId: Snowflake): Binding | null {
        const b = this.data.bindings[userId];
        return b ? { userId, ...b } : null;
    }

    /** Set of every fingerprint we have ever been told to trust for someone (used as the encrypt allowlist). */
    trustedFingerprints(): Set<Fingerprint> {
        return new Set(Object.values(this.data.bindings).map(b => b.fingerprint));
    }

    async bind(userId: Snowflake, fingerprint: Fingerprint): Promise<Binding> {
        const now = Date.now();
        const prev = this.data.bindings[userId];
        if (prev && prev.fingerprint === fingerprint) return { userId, ...prev };
        this.data.bindings[userId] = prev
            ? {
                fingerprint,
                verified: false, // a changed key is never carried over as verified
                addedAt: prev.addedAt,
                changedAt: now,
                previousFingerprints: [...prev.previousFingerprints, prev.fingerprint].slice(-10),
            }
            : { fingerprint, verified: false, addedAt: now, changedAt: null, previousFingerprints: [] };
        await this.save();
        return { userId, ...this.data.bindings[userId] };
    }

    async setVerified(userId: Snowflake, fingerprint: Fingerprint, verified: boolean): Promise<Binding | null> {
        const b = this.data.bindings[userId];
        if (!b || b.fingerprint !== fingerprint) return null;
        b.verified = verified;
        await this.save();
        return { userId, ...b };
    }

    async unbind(userId: Snowflake): Promise<boolean> {
        if (!this.data.bindings[userId]) return false;
        delete this.data.bindings[userId];
        await this.save();
        return true;
    }
}

function sanitize(input: unknown): FileShape {
    const out: FileShape = { version: 1, bindings: {} };
    if (typeof input !== "object" || input === null) return out;
    const { bindings } = input as any;
    if (typeof bindings !== "object" || bindings === null) return out;
    for (const [userId, v] of Object.entries(bindings as Record<string, any>)) {
        if (!SNOWFLAKE_RE.test(userId) || typeof v !== "object" || v === null) continue;
        if (typeof v.fingerprint !== "string" || !FINGERPRINT_RE.test(v.fingerprint)) continue;
        out.bindings[userId] = {
            fingerprint: v.fingerprint,
            verified: v.verified === true,
            addedAt: Number.isFinite(v.addedAt) ? v.addedAt : Date.now(),
            changedAt: Number.isFinite(v.changedAt) ? v.changedAt : null,
            previousFingerprints: Array.isArray(v.previousFingerprints)
                ? v.previousFingerprints.filter((f: unknown) => typeof f === "string" && FINGERPRINT_RE.test(f)).slice(-10)
                : [],
        };
    }
    return out;
}
