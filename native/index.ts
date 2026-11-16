/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * The IPC surface. Vencord registers every export here as
 * `VencordPluginNative_DiscordPG_<name>` and the renderer calls them through
 * `VencordNative.pluginHelpers.DiscordPG`. The renderer is untrusted: each
 * entry point validates its arguments with schema.ts before doing anything,
 * trust-changing calls go through native dialogs (confirm.ts), and nothing
 * here ever returns or accepts secret key material.
 */

import { DATA_DIR } from "@main/utils/constants";
import { RendererSettings } from "@main/settings";
import type { IpcMainInvokeEvent } from "electron";

import { looksArmored } from "../core/files";
import { ARMOR_MAX_BYTES, ATTACHMENT_MAX_BYTES, AttachmentDecryptResult, AttachmentEncryptResult, BackendStatus, Binding, DecryptResult, EncryptResult, fail, Failure, ImportResult, KeyInfo, NATIVE_API_VERSION, Result, SIGN_RATE_LIMIT, SignResult, VerifyResult } from "../core/types";
import { BindingStore } from "./bindings";
import { confirmBind, confirmSignOnly, confirmUnbind, confirmVerify, saveDecryptedFile } from "./confirm";
import { download, DownloadError } from "./download";
import { findGpg } from "./gpg";
import * as schema from "./schema";
import { GpgService } from "./service";

const PLUGIN_NAME = "DiscordPG";

interface PluginSettingsShape {
    gpgPath?: string;
    decryptTimeoutSeconds?: number;
    hideRecipientKeyIds?: boolean;
}

/** Settings are renderer-controlled; only use them for things the renderer could legitimately choose anyway. */
function pluginSettings(): PluginSettingsShape {
    const s = (RendererSettings.store.plugins as any)?.[PLUGIN_NAME] ?? {};
    return {
        gpgPath: typeof s.gpgPath === "string" ? s.gpgPath : undefined,
        decryptTimeoutSeconds: clampInt(s.decryptTimeoutSeconds, 10, 600, 120),
        hideRecipientKeyIds: s.hideRecipientKeyIds === true,
    };
}

const clampInt = (v: unknown, min: number, max: number, dflt: number) =>
    typeof v === "number" && Number.isFinite(v) ? Math.min(max, Math.max(min, Math.round(v))) : dflt;

const bindings = new BindingStore(BindingStore.defaultPath(DATA_DIR));

async function service(): Promise<Result<{ svc: GpgService }>> {
    const settings = pluginSettings();
    const found = await findGpg(settings.gpgPath ?? null);
    if (!found.path) return fail("gpg-missing", found.reason);
    await bindings.load();
    return {
        ok: true,
        svc: new GpgService({
            gpgPath: found.path,
            bindings,
            timeoutMs: (settings.decryptTimeoutSeconds ?? 120) * 1000,
            hideRecipientKeyIds: settings.hideRecipientKeyIds ?? false,
            saver: saveDecryptedFile,
        }),
    };
}

/** Turn thrown ValidationErrors (and anything else) into a Failure instead of leaking stack traces to the renderer. */
async function guarded<T>(fn: () => Promise<Result<T>>): Promise<Result<T>> {
    try {
        return await fn();
    } catch (e) {
        if (e instanceof schema.ValidationError) return fail("invalid-args", e.message);
        return fail("gpg-error", "internal error");
    }
}

/** Lets the renderer detect a stale main process (see NATIVE_API_VERSION). */
export function apiVersion(_: IpcMainInvokeEvent): Promise<number> {
    return Promise.resolve(NATIVE_API_VERSION);
}

export function status(_: IpcMainInvokeEvent): Promise<BackendStatus> {
    return (async () => {
        const settings = pluginSettings();
        const found = await findGpg(settings.gpgPath ?? null);
        await bindings.load();
        const base: BackendStatus = {
            gpgPath: found.path,
            gpgReason: found.path ? null : (found.reason ?? "gpg not found"),
            gpgVersion: null,
            libgcryptVersion: null,
            agentReachable: false,
            cardPresent: null,
            cardSerial: null,
            bindingsPath: bindings.path,
            bindingsCount: bindings.all().length,
        };
        if (!found.path) return base;
        const svc = new GpgService({ gpgPath: found.path, bindings, timeoutMs: 15_000, hideRecipientKeyIds: false });
        const v = await svc.version();
        const card = await svc.cardStatus().catch(() => ({ present: false, serial: null }));
        const keys = await svc.listSecretKeys();
        return {
            ...base,
            gpgVersion: v.gpg,
            libgcryptVersion: v.libgcrypt,
            agentReachable: keys.ok,
            cardPresent: card.present,
            cardSerial: card.serial,
        };
    })();
}

export function listSecretKeys(_: IpcMainInvokeEvent): Promise<Result<{ keys: KeyInfo[] }>> {
    return guarded(async () => {
        const s = await service();
        if (!s.ok) return s;
        return s.svc.listSecretKeys(true);
    });
}

export function exportPublicKey(_: IpcMainInvokeEvent, fingerprint: unknown): Promise<Result<{ armored: string }>> {
    return guarded(async () => {
        const fpr = schema.fingerprint(fingerprint);
        const s = await service();
        if (!s.ok) return s;
        return s.svc.exportPublicKey(fpr);
    });
}

/** Imports the key into the keyring. Does NOT bind it to anyone; that is a separate, confirmed step. */
export function importPublicKey(_: IpcMainInvokeEvent, armored: unknown): Promise<ImportResult> {
    return guarded(async () => {
        const text = schema.armorText(armored);
        const s = await service();
        if (!s.ok) return s;
        return s.svc.importPublicKey(text);
    });
}

export function getBindings(_: IpcMainInvokeEvent): Promise<Result<{ bindings: Binding[] }>> {
    return guarded(async () => {
        await bindings.load();
        return { ok: true, bindings: bindings.all() };
    });
}

export function bindKey(_: IpcMainInvokeEvent, req: unknown): Promise<Result<{ binding: Binding }>> {
    return guarded(async () => {
        const r = schema.bindRequest(req);
        const s = await service();
        if (!s.ok) return s;
        // The key must actually exist in the keyring and be usable before we let the user trust it, and the
        // fingerprint must be that key's own primary fingerprint, not a subkey of some other key.
        const found = await s.svc.resolveExact([r.fingerprint]);
        if (!found.ok) return found.error === "invalid-recipient" ? fail("malformed", "key is not in the keyring; import it first") : found;
        const [key] = found.keys;
        if (key.revoked) return fail("key-revoked");
        const prev = bindings.get(r.userId);
        if (prev && prev.fingerprint === r.fingerprint) return { ok: true, binding: prev };
        const yes = await confirmBind({ userLabel: r.userLabel, userId: r.userId, fingerprint: r.fingerprint, previous: prev?.fingerprint ?? null });
        if (!yes) return fail("cancelled");
        return { ok: true, binding: await bindings.bind(r.userId, r.fingerprint) };
    });
}

export function setVerified(_: IpcMainInvokeEvent, req: unknown): Promise<Result<{ binding: Binding }>> {
    return guarded(async () => {
        const r = schema.verifyRequest(req);
        await bindings.load();
        const cur = bindings.get(r.userId);
        if (!cur || cur.fingerprint !== r.fingerprint) return fail("invalid-args", "no such binding");
        if (cur.verified) return { ok: true, binding: cur };
        const yes = await confirmVerify({ userLabel: r.userLabel, userId: r.userId, fingerprint: r.fingerprint });
        if (!yes) return fail("cancelled");
        const b = await bindings.setVerified(r.userId, r.fingerprint, true);
        return b ? { ok: true, binding: b } : fail("invalid-args", "no such binding");
    });
}

export function unbindKey(_: IpcMainInvokeEvent, req: unknown): Promise<Result<{ removed: boolean }>> {
    return guarded(async () => {
        const r = schema.verifyRequest(req);
        await bindings.load();
        const cur = bindings.get(r.userId);
        if (!cur) return { ok: true, removed: false };
        const yes = await confirmUnbind({ userLabel: r.userLabel, userId: r.userId, fingerprint: cur.fingerprint });
        if (!yes) return fail("cancelled");
        return { ok: true, removed: await bindings.unbind(r.userId) };
    });
}

export function encryptAndSign(_: IpcMainInvokeEvent, req: unknown): Promise<EncryptResult> {
    return guarded(async () => {
        const r = schema.encryptRequest(req);
        const s = await service();
        if (!s.ok) return s;
        return s.svc.encryptAndSign(r);
    });
}

export function decrypt(_: IpcMainInvokeEvent, req: unknown): Promise<DecryptResult> {
    return guarded(async () => {
        const r = schema.decryptRequest(req);
        const s = await service();
        if (!s.ok) return s;
        return s.svc.decrypt(r);
    });
}

export function encryptAttachment(_: IpcMainInvokeEvent, req: unknown): Promise<AttachmentEncryptResult> {
    return guarded(async () => {
        const r = schema.encryptAttachmentRequest(req);
        const s = await service();
        if (!s.ok) return s;
        return s.svc.encryptAttachment(r);
    });
}

/** Download from Discord's CDN with the failure mapped to a Result; never throws. */
async function fetchAttachment(url: string, maxBytes: number): Promise<Result<{ data: Buffer }>> {
    try {
        return { ok: true, data: await download(url, maxBytes) };
    } catch (e) {
        if (e instanceof DownloadError) return e.oversize ? fail("oversize", "attachment too large") : fail("download-failed", e.message);
        return fail("download-failed");
    }
}

export function decryptAttachment(_: IpcMainInvokeEvent, req: unknown): Promise<AttachmentDecryptResult> {
    return guarded(async () => {
        const { url, ...r } = schema.decryptAttachmentRequest(req);
        const s = await service();
        if (!s.ok) return s;
        const dl = await fetchAttachment(url, ATTACHMENT_MAX_BYTES);
        if (!dl.ok) return dl;
        if (dl.data.length === 0) return fail("malformed", "empty file");
        return s.svc.decryptAttachment({ ...r, data: new Uint8Array(dl.data) });
    });
}

/** Small text attachments (.asc / message.txt) that should be a PGP block: downloaded here, parsed in the renderer. */
export function fetchArmored(_: IpcMainInvokeEvent, req: unknown): Promise<Result<{ text: string }>> {
    return guarded(async () => {
        const { url } = schema.fetchArmoredRequest(req);
        const dl = await fetchAttachment(url, ARMOR_MAX_BYTES);
        if (!dl.ok) return dl;
        // Tolerate a UTF-8 BOM and leading whitespace, which text editors like to add.
        const text = dl.data.toString("utf8").replace(/^\uFEFF/, "").trimStart();
        if (!looksArmored(Buffer.from(text, "utf8"))) return fail("malformed", "not a PGP block");
        return { ok: true, text };
    });
}

// Sign-only guards. Both reset on lock().
let signSessionAllowed = false;
const signTimes: number[] = [];
function takeSignToken(): boolean {
    const now = Date.now();
    while (signTimes.length && now - signTimes[0] > SIGN_RATE_LIMIT.perMs) signTimes.shift();
    if (signTimes.length >= SIGN_RATE_LIMIT.max) return false;
    signTimes.push(now);
    return true;
}

/** Sign without encrypting. OS confirmation once per session, then rate limited; see GpgService.sign for the rest. */
export function sign(_: IpcMainInvokeEvent, req: unknown): Promise<SignResult> {
    return guarded(async () => {
        const r = schema.signRequest(req);
        const s = await service();
        if (!s.ok) return s;
        if (!signSessionAllowed) {
            if (!(await confirmSignOnly({ fingerprint: r.signWith }))) return fail("cancelled");
            signSessionAllowed = true;
        }
        if (!takeSignToken()) return fail("gpg-error", `rate limit: at most ${SIGN_RATE_LIMIT.max} unencrypted signatures per minute`);
        return s.svc.sign(r);
    });
}

export function verify(_: IpcMainInvokeEvent, req: unknown): Promise<VerifyResult> {
    return guarded(async () => {
        const r = schema.verifySignatureRequest(req);
        const s = await service();
        if (!s.ok) return s;
        return s.svc.verify(r);
    });
}

export function lock(_: IpcMainInvokeEvent): Promise<Result<{}>> {
    return guarded(async () => {
        signSessionAllowed = false;
        signTimes.length = 0;
        const s = await service();
        if (!s.ok) return s;
        await s.svc.lock();
        return { ok: true };
    });
}

export type { Failure };
