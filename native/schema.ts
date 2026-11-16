/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Hand-written validators for everything that crosses the renderer -> main IPC
 * boundary. The renderer is untrusted; nothing it sends is used until it has
 * passed one of these. No dependencies on purpose.
 */

import { ARMOR_MAX_BYTES, ATTACHMENT_MAX_BYTES, ATTACHMENT_URL_HOSTS, ATTACHMENT_URL_PATH_RE, AttachmentAction, FINGERPRINT_RE, Fingerprint, MAX_RECIPIENTS, PLAINTEXT_MAX_BYTES, SIGN_TEXT_MAX_CHARS, Snowflake, SNOWFLAKE_RE, VerifyRequest } from "../core/types";

export class ValidationError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "ValidationError";
    }
}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

export function fingerprint(v: unknown, what = "fingerprint"): Fingerprint {
    if (typeof v !== "string" || !FINGERPRINT_RE.test(v)) throw new ValidationError(`${what}: expected 40 uppercase hex chars`);
    return v;
}

export function snowflake(v: unknown, what = "userId"): Snowflake {
    if (typeof v !== "string" || !SNOWFLAKE_RE.test(v)) throw new ValidationError(`${what}: expected a Discord snowflake`);
    return v;
}

export function boundedString(v: unknown, max: number, what: string): string {
    if (typeof v !== "string") throw new ValidationError(`${what}: expected a string`);
    if (v.length > max) throw new ValidationError(`${what}: exceeds ${max} characters`);
    if (v.includes("\0")) throw new ValidationError(`${what}: contains NUL`);
    return v;
}

/** Armor text as the renderer hands it over; structural validity is checked separately by core/wire parseArmor. */
export function armorText(v: unknown, what = "armored"): string {
    const s = boundedString(v, ARMOR_MAX_BYTES, what);
    if (!/^[\x09\x0a\x0d\x20-\x7e]*$/.test(s)) throw new ValidationError(`${what}: non-ASCII content`);
    return s;
}

export function plaintext(v: unknown): string {
    const s = boundedString(v, PLAINTEXT_MAX_BYTES, "plaintext");
    if (s.length === 0) throw new ValidationError("plaintext: empty");
    return s;
}

export function fingerprintList(v: unknown, max: number, what = "recipients"): Fingerprint[] {
    if (!Array.isArray(v) || v.length === 0 || v.length > max) throw new ValidationError(`${what}: expected 1..${max} fingerprints`);
    const out = v.map((f, i) => fingerprint(f, `${what}[${i}]`));
    if (new Set(out).size !== out.length) throw new ValidationError(`${what}: duplicates`);
    return out;
}

export function encryptRequest(v: unknown) {
    if (!isObj(v)) throw new ValidationError("encrypt: expected an object");
    return {
        plaintext: plaintext(v.plaintext),
        recipients: fingerprintList(v.recipients, MAX_RECIPIENTS),
        signWith: v.signWith == null ? null : fingerprint(v.signWith, "signWith"),
    };
}

export function decryptRequest(v: unknown) {
    if (!isObj(v)) throw new ValidationError("decrypt: expected an object");
    return {
        armored: armorText(v.armored),
        authorUserId: v.authorUserId == null ? null : snowflake(v.authorUserId, "authorUserId"),
        authorIsSelf: v.authorIsSelf === true,
        channelId: v.channelId == null ? null : snowflake(v.channelId, "channelId"),
    };
}

const CONTROL_CHARS = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/;

/** Text we are willing to sign without encrypting: short, printable, non-empty. */
export function signText(v: unknown, what = "text"): string {
    const s = boundedString(v, SIGN_TEXT_MAX_CHARS, what);
    if (!s.trim()) throw new ValidationError(`${what}: empty`);
    if (CONTROL_CHARS.test(s)) throw new ValidationError(`${what}: control characters`);
    return s;
}

export function signRequest(v: unknown) {
    if (!isObj(v)) throw new ValidationError("sign: expected an object");
    return {
        text: signText(v.text),
        channelId: snowflake(v.channelId, "channelId"),
        signWith: fingerprint(v.signWith, "signWith"),
    };
}

export function verifySignatureRequest(v: unknown): VerifyRequest {
    if (!isObj(v)) throw new ValidationError("verify: expected an object");
    const base = {
        channelId: v.channelId == null ? null : snowflake(v.channelId, "channelId"),
        authorUserId: v.authorUserId == null ? null : snowflake(v.authorUserId, "authorUserId"),
        authorIsSelf: v.authorIsSelf === true,
    };
    if (v.kind === "detached") return { ...base, kind: "detached", text: signText(v.text), signature: armorText(v.signature, "signature") };
    if (v.kind === "clearsign" || v.kind === "encoded") {
        // Clearsigned text may contain Unicode, so only the size / NUL rules apply here; the grammar is checked in parseArmor.
        return { ...base, kind: v.kind, armored: boundedString(v.armored, ARMOR_MAX_BYTES, "armored") };
    }
    throw new ValidationError("verify: kind must be clearsign, encoded or detached");
}

/** Binary payloads arrive through structured clone as Uint8Array (or ArrayBuffer). Never a string: no base64 ambiguity. */
export function bytes(v: unknown, max: number, what: string): Uint8Array {
    let u: Uint8Array;
    if (v instanceof Uint8Array) u = v;
    else if (v instanceof ArrayBuffer) u = new Uint8Array(v);
    else throw new ValidationError(`${what}: expected binary data`);
    if (u.byteLength === 0) throw new ValidationError(`${what}: empty`);
    if (u.byteLength > max) throw new ValidationError(`${what}: exceeds ${max} bytes`);
    return u;
}

/**
 * The renderer names what the main process downloads. Only Discord's attachment CDNs over https, so a hostile
 * renderer cannot turn this into a request to localhost, the LAN or an arbitrary site. Credentials in the
 * URL are refused; query strings (the CDN's signed ex/is/hm parameters) are kept as is.
 */
export function attachmentUrl(v: unknown, what = "url"): string {
    if (typeof v !== "string" || v.length === 0 || v.length > 2048) throw new ValidationError(`${what}: expected a URL`);
    let u: URL;
    try { u = new URL(v); } catch { throw new ValidationError(`${what}: not a valid URL`); }
    if (u.protocol !== "https:") throw new ValidationError(`${what}: must be https`);
    if (u.username || u.password) throw new ValidationError(`${what}: credentials not allowed`);
    if (!ATTACHMENT_URL_HOSTS.includes(u.hostname) || u.port !== "") throw new ValidationError(`${what}: not a Discord attachment host`);
    if (!ATTACHMENT_URL_PATH_RE.test(u.pathname)) throw new ValidationError(`${what}: not an attachment path`);
    return u.toString();
}

export function fetchArmoredRequest(v: unknown) {
    if (!isObj(v)) throw new ValidationError("fetchArmored: expected an object");
    return { url: attachmentUrl(v.url) };
}

/**
 * A file name chosen by a remote sender is untrusted: keep only the final path component, drop control
 * characters and leading dots, and never let it be empty. Used for suggested save names and gpg metadata.
 */
export function safeFilename(v: unknown, what = "filename"): string {
    const raw = boundedString(v, 255, what);
    let s = raw.split(/[\\/]/).pop() ?? "";
    s = s.replace(/[\x00-\x1f\x7f]/g, "").replace(/^[.\s]+/, "").trim();
    if (!s || s === "..") s = "attachment";
    return s;
}

const ATTACHMENT_ACTIONS: readonly AttachmentAction[] = ["preview", "save"];

export function encryptAttachmentRequest(v: unknown) {
    if (!isObj(v)) throw new ValidationError("encryptAttachment: expected an object");
    return {
        data: bytes(v.data, ATTACHMENT_MAX_BYTES, "data"),
        filename: safeFilename(v.filename),
        recipients: fingerprintList(v.recipients, MAX_RECIPIENTS),
        signWith: v.signWith == null ? null : fingerprint(v.signWith, "signWith"),
    };
}

export function decryptAttachmentRequest(v: unknown) {
    if (!isObj(v)) throw new ValidationError("decryptAttachment: expected an object");
    if (!ATTACHMENT_ACTIONS.includes(v.action as AttachmentAction)) throw new ValidationError("decryptAttachment: action must be preview or save");
    return {
        url: attachmentUrl(v.url),
        filename: safeFilename(v.filename),
        authorUserId: v.authorUserId == null ? null : snowflake(v.authorUserId, "authorUserId"),
        authorIsSelf: v.authorIsSelf === true,
        action: v.action as AttachmentAction,
    };
}

export function bindRequest(v: unknown) {
    if (!isObj(v)) throw new ValidationError("bind: expected an object");
    return {
        userId: snowflake(v.userId),
        fingerprint: fingerprint(v.fingerprint),
        /** Display-only label shown in the native confirmation dialog, e.g. "alice (Alice#0)". */
        userLabel: boundedString(v.userLabel, 120, "userLabel").replace(/[^\x20-\x7e -￿]/g, "?"),
    };
}

export function verifyRequest(v: unknown) {
    if (!isObj(v)) throw new ValidationError("verify: expected an object");
    return {
        userId: snowflake(v.userId),
        fingerprint: fingerprint(v.fingerprint),
        userLabel: boundedString(v.userLabel, 120, "userLabel"),
    };
}
