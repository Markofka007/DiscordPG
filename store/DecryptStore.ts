/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * In-memory (and only in-memory) store of decryption results, keyed by message
 * id. Cleared on lock, on plugin stop, and by the idle auto-lock timer.
 */

import { updateMessage } from "@api/MessageUpdater";
import { Logger } from "@utils/Logger";
import type { Message, MessageAttachment } from "@vencord/discord-types";
import { useEffect, UserStore, useState } from "@webpack/common";

import { gpgBackend } from "../core/backend";
import { DecryptEntry, hiddenFor } from "../core/display";
import { strippedName } from "../core/files";
import { AttachmentAction, DecryptResult, ErrorCode, SigVerdict } from "../core/types";
import { extractArmor, extractDetachedSigned, fnv1a64, parseArmor } from "../core/wire";
import { settings } from "../settings";

const logger = new Logger("DiscordPG");

export type { DecryptEntry };
export { hiddenFor };

export interface DecryptRecord {
    messageId: string;
    channelId: string;
    contentHash: string;
    entry: DecryptEntry;
    showOriginal: boolean;
    /** Plain text followed by a PGP SIGNATURE block (the "detached" sign-only style). */
    detached: boolean;
}

/** How a message is protected on the wire, as far as we can tell before asking gpg. */
type WireKind =
    | { kind: "encrypted"; armored: string }   // PGP MESSAGE: encrypted, or the "encoded" sign-only style
    | { kind: "clearsign"; armored: string }
    | { kind: "detached"; text: string; signature: string };

function wireKindOf(message: Message): WireKind | null {
    const content = message.content ?? "";
    const block = extractArmor(content);
    if (block?.kind === "MESSAGE") return { kind: "encrypted", armored: block.armored };
    if (block?.kind === "SIGNED MESSAGE") return { kind: "clearsign", armored: block.armored };
    if (block) return null; // public key / bare signature: not a message to decrypt
    const detached = extractDetachedSigned(content);
    return detached ? { kind: "detached", ...detached } : null;
}

const detachedKey = (text: string, signature: string) => fnv1a64(`detached:${text}\n${signature}`);
const wireHash = (w: WireKind) => w.kind === "detached" ? detachedKey(w.text, w.signature) : fnv1a64(w.armored);

const records = new Map<string, DecryptRecord>();
const listeners = new Map<string, Set<() => void>>();
const inFlight = new Map<string, Promise<void>>();
/**
 * fnv of outgoing armor -> plaintext, so our own just-sent messages render decrypted without a card round trip.
 * Entries are NOT consumed on use: Discord renders the local "SENDING" copy (id = nonce) first and the
 * confirmed message (real id) afterwards, and both must find the plaintext. They expire instead.
 */
const optimistic = new Map<string, { plaintext: string; fingerprint: string; at: number; mode: "encrypted" | "signed" }>();
const OPTIMISTIC_TTL_MS = 10 * 60_000;
const OPTIMISTIC_MAX = 50;
const startedAt = Date.now();

let onActivity: (() => void) | null = null;
export function setActivityHook(fn: (() => void) | null) { onActivity = fn; }
const touch = () => onActivity?.();

function emit(messageId: string) {
    listeners.get(messageId)?.forEach(fn => { try { fn(); } catch (e) { logger.error(e); } });
}

export function subscribe(messageId: string, fn: () => void): () => void {
    let set = listeners.get(messageId);
    if (!set) listeners.set(messageId, set = new Set());
    set.add(fn);
    return () => {
        set!.delete(fn);
        if (set!.size === 0) listeners.delete(messageId);
    };
}

export function getRecord(messageId: string): DecryptRecord | undefined {
    return records.get(messageId);
}

/** Used by the <li> className patch. */
export function isHidden(messageId: string): boolean {
    const r = records.get(messageId);
    return !!r && hiddenFor(r.entry, r.showOriginal);
}

function rerender(r: DecryptRecord) {
    emit(r.messageId);
    try { updateMessage(r.channelId, r.messageId); } catch { /* message may have scrolled out of the cache */ }
}

function shouldAutoDecrypt(message: Message): boolean {
    switch (settings.store.autoDecrypt as string) {
        case "manual": return false;
        case "newOnly": return new Date(message.timestamp).getTime() >= startedAt;
        default: return true;
    }
}

/**
 * Make sure a record exists for this message and, policy permitting, start
 * decrypting. Returns null when the message is not an armored PGP message.
 */
export function ensure(message: Message, opts: { force?: boolean } = {}): DecryptRecord | null {
    const wire = wireKindOf(message);
    if (!wire) {
        if (records.has(message.id)) { records.delete(message.id); queueMicrotask(() => emit(message.id)); }
        return null;
    }
    const contentHash = wireHash(wire);
    let r = records.get(message.id);
    if (r && r.contentHash !== contentHash) r = undefined; // edited: start over

    if (!r) {
        r = { messageId: message.id, channelId: message.channel_id, contentHash, entry: { state: "idle" }, showOriginal: false, detached: wire.kind === "detached" };
        records.set(message.id, r);
        const opt = optimistic.get(contentHash);
        if (opt && Date.now() - opt.at > OPTIMISTIC_TTL_MS) optimistic.delete(contentHash);
        else if (opt) {
            r.entry = {
                state: "ok",
                plaintext: opt.plaintext,
                signature: { status: "none" },
                verdict: { kind: "self", fingerprint: opt.fingerprint },
                encryptedTo: [],
                mode: opt.mode,
            };
        }
    }

    if (r.entry.state === "idle" && (opts.force || shouldAutoDecrypt(message))) {
        void decryptRecord(r, wire, message);
    }
    return r;
}

async function decryptRecord(r: DecryptRecord, wire: WireKind, message: Message): Promise<void> {
    if (inFlight.has(r.messageId)) return inFlight.get(r.messageId);
    r.entry = { state: "pending" };
    // ensure() may run during React render (see liClass in index.tsx); never setState other components synchronously from there.
    queueMicrotask(() => emit(r.messageId));
    touch();

    const me = UserStore.getCurrentUser()?.id;
    const authorId = message.author?.id ?? null;
    const who = { authorUserId: authorId, authorIsSelf: !!me && authorId === me, channelId: message.channel_id };

    const task = (async () => {
        let res: DecryptResult;
        if (wire.kind === "encrypted") res = await gpgBackend.decrypt({ armored: wire.armored, ...who });
        else if (wire.kind === "clearsign") res = await gpgBackend.verify({ kind: "clearsign", armored: wire.armored, ...who });
        else res = await gpgBackend.verify({ kind: "detached", text: wire.text, signature: wire.signature, ...who });
        // The record may have been replaced (edit) or evicted meanwhile.
        if (records.get(r.messageId) !== r) return;
        r.entry = res.ok
            ? { state: "ok", plaintext: res.plaintext, signature: res.signature, verdict: res.verdict, encryptedTo: res.encryptedTo, mode: res.mode, channelMismatch: res.channelMismatch }
            : { state: "error", error: res.error, detail: res.detail };
        rerender(r);
    })().catch(e => {
        logger.error("decrypt failed", e);
        if (records.get(r.messageId) === r) { r.entry = { state: "error", error: "gpg-error" }; rerender(r); }
    }).finally(() => inFlight.delete(r.messageId));
    inFlight.set(r.messageId, task);
    return task;
}

export function retry(message: Message) {
    const r = records.get(message.id);
    if (r) r.entry = { state: "idle" };
    ensure(message, { force: true });
}

export function toggleOriginal(messageId: string) {
    const r = records.get(messageId);
    if (!r) return;
    r.showOriginal = !r.showOriginal;
    rerender(r);
}

export function evict(messageId: string) {
    const had = records.delete(messageId);
    for (const k of [...attachments.keys()]) if (k.startsWith(messageId + ":")) dropAttachment(k);
    if (had) emit(messageId);
}

function rememberKey(key: string, plaintext: string, fingerprint: string, mode: "encrypted" | "signed") {
    const now = Date.now();
    for (const [k, v] of optimistic) if (now - v.at > OPTIMISTIC_TTL_MS) optimistic.delete(k);
    // Bound the map so a stuck send cannot grow it forever.
    while (optimistic.size >= OPTIMISTIC_MAX) {
        const oldest = [...optimistic.entries()].sort((a, b) => a[1].at - b[1].at)[0];
        if (!oldest) break;
        optimistic.delete(oldest[0]);
    }
    optimistic.set(key, { plaintext, fingerprint, at: now, mode });
}

/** Keyed by the canonical armor (headers stripped), i.e. exactly what wireKindOf will see when the message arrives. */
export const rememberOutgoing = (armored: string, plaintext: string, fingerprint: string, mode: "encrypted" | "signed") =>
    rememberKey(fnv1a64(parseArmor(armored)?.armored ?? armored), plaintext, fingerprint, mode);

/** Forget every plaintext we hold, including decrypted attachment previews. */
export function clearAll() {
    const ids = new Set([...records.keys(), ...[...attachments.keys()].map(k => k.split(":")[0])]);
    records.clear();
    optimistic.clear();
    for (const k of [...attachments.keys()]) dropAttachment(k);
    for (const id of ids) emit(id);
}

// ---------------------------------------------------------------------------------------------------------
// Encrypted attachments (.gpg / .pgp / .asc files). Downloads and decryption happen in the main process;
// previews are object URLs over decrypted bytes and live exactly as long as the text plaintext does.

export type AttachmentEntry =
    // Small .asc / .txt files are probed on sight to find out what they are.
    | { state: "probing" }
    | { state: "plain" }                          // not a PGP block: ignore
    | { state: "key"; armored: string }           // a public key: offer import
    | { state: "message" }                        // an armored PGP message: offer Preview / Decrypt & save
    | { state: "pending"; action: AttachmentAction }
    | { state: "preview"; url: string; mime: string; verdict: SigVerdict; size: number; savedTo?: string }
    | { state: "saved"; savedTo: string; verdict: SigVerdict; size: number }
    | { state: "error"; action: AttachmentAction | null; error: ErrorCode; detail?: string };

const attachments = new Map<string, AttachmentEntry>();
const akey = (messageId: string, attachmentId: string) => `${messageId}:${attachmentId}`;

function dropAttachment(k: string) {
    const e = attachments.get(k);
    if (e?.state === "preview") { try { URL.revokeObjectURL(e.url); } catch { /* ignore */ } }
    attachments.delete(k);
}

function setAttachment(messageId: string, attachmentId: string, e: AttachmentEntry | null) {
    const k = akey(messageId, attachmentId);
    const prev = attachments.get(k);
    if (prev?.state === "preview" && (!e || e.state !== "preview" || e.url !== prev.url)) { try { URL.revokeObjectURL(prev.url); } catch { /* ignore */ } }
    if (e) attachments.set(k, e); else attachments.delete(k);
    emit(messageId);
}

export const getAttachment = (messageId: string, attachmentId: string) => attachments.get(akey(messageId, attachmentId));

/**
 * Find out what a small .asc / .txt attachment is: a public key (offer import), a PGP message (offer
 * decryption) or neither. Idempotent; the result is cached per attachment until the message is evicted.
 */
export function probeAttachment(message: Message, att: MessageAttachment): void {
    const k = akey(message.id, att.id);
    if (attachments.has(k)) return;
    attachments.set(k, { state: "probing" });
    void (async () => {
        let next: AttachmentEntry;
        try {
            const r = await gpgBackend.fetchArmored({ url: att.url });
            if (!r.ok) next = r.error === "malformed" ? { state: "plain" } : { state: "error", action: null, error: r.error, detail: r.detail };
            else {
                const block = parseArmor(r.text);
                next = block?.kind === "PUBLIC KEY BLOCK" ? { state: "key", armored: block.armored }
                    : block?.kind === "MESSAGE" ? { state: "message" }
                        : { state: "plain" };
            }
        } catch (e) {
            logger.error("probe failed", e);
            next = { state: "plain" };
        }
        if (attachments.get(k)?.state === "probing") setAttachment(message.id, att.id, next);
    })();
}

/**
 * Decrypt an attachment: the main process downloads it and either hands image bytes back for an inline
 * <img> ("preview") or writes the file where the user picks ("save"; plaintext never reaches the renderer).
 */
export async function processAttachment(message: Message, att: MessageAttachment, action: AttachmentAction): Promise<void> {
    const k = akey(message.id, att.id);
    const prev = attachments.get(k);
    if (prev?.state === "pending" || prev?.state === "probing") return;
    // Keep an existing preview on screen while saving from it.
    if (!(prev?.state === "preview" && action === "save")) setAttachment(message.id, att.id, { state: "pending", action });
    touch();

    const failWith = (error: ErrorCode, detail?: string) => setAttachment(message.id, att.id, { state: "error", action, error, detail });
    try {
        const me = UserStore.getCurrentUser()?.id;
        const authorId = message.author?.id ?? null;
        const r = await gpgBackend.decryptAttachment({ url: att.url, filename: strippedName(att.filename ?? ""), authorUserId: authorId, authorIsSelf: !!me && authorId === me, action });
        if (!r.ok) {
            if (r.error === "cancelled") setAttachment(message.id, att.id, prev?.state === "preview" ? prev : null);
            else failWith(r.error, r.detail);
            return;
        }
        if (r.action === "preview") {
            const url = URL.createObjectURL(new Blob([r.data as BlobPart], { type: r.mime }));
            setAttachment(message.id, att.id, { state: "preview", url, mime: r.mime, verdict: r.verdict, size: r.size });
        } else if (prev?.state === "preview") {
            setAttachment(message.id, att.id, { ...prev, savedTo: r.savedTo });
        } else {
            setAttachment(message.id, att.id, { state: "saved", savedTo: r.savedTo, verdict: r.verdict, size: r.size });
        }
    } catch (e) {
        logger.error("attachment failed", e);
        failWith("gpg-error", "internal error");
    }
}

export function size() { return records.size; }

/** React hook: current record for a message, re-rendering on changes. */
export function useDecryptRecord(message: Message): DecryptRecord | null {
    const [, bump] = useState(0);
    useEffect(() => subscribe(message.id, () => bump(n => n + 1)), [message.id]);
    useEffect(() => { ensure(message); }, [message.id, message.content]);
    return records.get(message.id) ?? null;
}
