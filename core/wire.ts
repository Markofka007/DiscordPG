/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * The on-the-wire format: standard OpenPGP ASCII armor, optionally wrapped in a
 * Discord code fence. Parsing is deliberately line-based (no catastrophic
 * regexes over attacker-controlled input) and strict: anything that does not
 * look exactly like RFC 9580 §6.2 armor is rejected before it gets near gpg.
 */

import { ARMOR_MAX_BYTES, SIGN_TEXT_MAX_CHARS } from "./types";

export type ArmorKind = "MESSAGE" | "PUBLIC KEY BLOCK" | "SIGNATURE" | "SIGNED MESSAGE";

export interface ArmoredBlock {
    kind: ArmorKind;
    /** Canonical armor: LF line endings, no trailing whitespace, exactly as passed to gpg. */
    armored: string;
    /** Offsets of the block (including any code fence) inside the original content. */
    start: number;
    end: number;
}

const KINDS: readonly ArmorKind[] = ["MESSAGE", "PUBLIC KEY BLOCK", "SIGNATURE", "SIGNED MESSAGE"];
const BEGIN = (k: ArmorKind) => `-----BEGIN PGP ${k}-----`;
const END = (k: ArmorKind) => `-----END PGP ${k}-----`;

const BASE64_LINE = /^[A-Za-z0-9+/]+={0,2}$/;
const CRC_LINE = /^=[A-Za-z0-9+/]{4}$/;
/**
 * "Key: value" armor header. Real-world exporters are sloppy here: Kleopatra separates key and value with a
 * TAB, user IDs in "Comment:" headers carry any Unicode, and empty values occur. Headers carry no
 * cryptographic meaning (except "Hash:" in cleartext signatures, handled separately), so we accept anything
 * without control characters and then DROP them: the canonical armor we hand to gpg never contains them.
 */
const HEADER_LINE = /^[A-Za-z][A-Za-z0-9-]*:(?:[ \t][^\x00-\x08\x0a-\x1f\x7f]*)?$/;
/** Cleartext-signature header: only "Hash: <algos>" (RFC 9580 §7.2), printable ASCII. */
const CLEAR_HEADER_LINE = /^Hash: [\x20-\x7e]+$/;
const PRINTABLE_ASCII_OR_WS = /^[\x09\x0a\x0d\x20-\x7e]*$/;
// Clearsigned text may be any Unicode, but never raw control characters.
const CONTROL_CHARS = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/;

/**
 * Parse a string that should be exactly one armored block (leading/trailing
 * whitespace tolerated). Returns the canonical armor or null.
 */
export function parseArmor(text: string, expectKind?: ArmorKind, opts: { maxBytes?: number } = {}): { kind: ArmorKind; armored: string } | null {
    if (typeof text !== "string") return null;
    if (text.length > (opts.maxBytes ?? ARMOR_MAX_BYTES)) return null;

    const lines = text.replace(/\r\n?/g, "\n").split("\n").map(l => l.replace(/[ \t]+$/, ""));
    // strip leading/trailing blank lines
    while (lines.length && lines[0] === "") lines.shift();
    while (lines.length && lines[lines.length - 1] === "") lines.pop();
    if (lines.length < 3) return null;

    const kind = KINDS.find(k => lines[0] === BEGIN(k));
    if (!kind || (expectKind && kind !== expectKind)) return null;
    if (kind === "SIGNED MESSAGE") return parseClearsigned(lines);
    return parseArmorLines(lines, kind);
}

/**
 * RFC 9580 §7 cleartext signature framework: BEGIN PGP SIGNED MESSAGE, "Hash:" headers, blank line, the
 * (dash-escaped) text, then a regular SIGNATURE armor. The text part may be any Unicode without control chars.
 */
function parseClearsigned(lines: string[]): { kind: ArmorKind; armored: string } | null {
    if (lines[lines.length - 1] !== END("SIGNATURE")) return null;
    let i = 1;
    while (i < lines.length && lines[i] !== "") {
        if (!CLEAR_HEADER_LINE.test(lines[i])) return null;
        i++;
    }
    if (lines[i] !== "") return null;
    i++;
    const sigStart = lines.indexOf(BEGIN("SIGNATURE"), i);
    if (sigStart === -1 || sigStart === i) return null; // no text at all is not a message
    for (let j = i; j < sigStart; j++) {
        if (CONTROL_CHARS.test(lines[j])) return null;
        if (lines[j].startsWith("-----")) return null; // gpg dash-escapes these; a raw one means a forged frame
    }
    if (!parseArmorLines(lines.slice(sigStart), "SIGNATURE")) return null;
    return { kind: "SIGNED MESSAGE", armored: lines.join("\n") + "\n" };
}

/**
 * Standard armor (everything but the cleartext framework); `lines` already normalised. Returns canonical armor
 * WITHOUT the header lines (see HEADER_LINE), so the output is always printable ASCII.
 */
function parseArmorLines(lines: string[], kind: ArmorKind): { kind: ArmorKind; armored: string } | null {
    if (lines.length < 3) return null;
    if (lines[0] !== BEGIN(kind)) return null;
    if (lines[lines.length - 1] !== END(kind)) return null;

    let i = 1;
    // optional armor headers, terminated by a blank line
    let sawHeader = false;
    while (i < lines.length - 1 && lines[i] !== "") {
        if (!HEADER_LINE.test(lines[i])) {
            // No headers at all: body may start immediately (gpg always emits the blank line, but be lenient)
            if (!sawHeader && BASE64_LINE.test(lines[i])) break;
            return null;
        }
        sawHeader = true;
        i++;
    }
    if (lines[i] === "") i++;

    // body: >=1 base64 line, optional CRC line, then END
    const body: string[] = [];
    let sawCrc = false;
    for (; i < lines.length - 1; i++) {
        const l = lines[i];
        if (sawCrc) return null; // nothing may follow the CRC except END
        if (!PRINTABLE_ASCII_OR_WS.test(l)) return null;
        if (CRC_LINE.test(l)) { sawCrc = true; body.push(l); continue; }
        if (!BASE64_LINE.test(l)) return null;
        if (l.includes("=") && i !== lines.length - 2 && !CRC_LINE.test(lines[i + 1])) {
            // padding is only legal on the final body line
            return null;
        }
        body.push(l);
    }
    if (body.length === 0 || (body.length === 1 && sawCrc)) return null;

    return { kind, armored: [lines[0], "", ...body, lines[lines.length - 1]].join("\n") + "\n" };
}

/**
 * Locate an armored block inside arbitrary Discord message content. Tolerates
 * a surrounding ``` fence (with or without a language tag) and surrounding
 * whitespace, but nothing else: a message must *be* the block, not merely contain one.
 */
export function extractArmor(content: string, expectKind?: ArmorKind): ArmoredBlock | null {
    if (typeof content !== "string" || content.length > ARMOR_MAX_BYTES + 32) return null;
    const trimmed = content.trim();
    if (!trimmed.startsWith("```") && !trimmed.startsWith("-----BEGIN PGP ")) return null;

    let inner = trimmed;
    if (inner.startsWith("```")) {
        if (!inner.endsWith("```") || inner.length < 6) return null;
        inner = inner.slice(3, -3);
        // optional language tag on the opening fence
        const nl = inner.indexOf("\n");
        if (nl === -1) return null;
        const firstLine = inner.slice(0, nl);
        if (firstLine !== "" && !/^[A-Za-z0-9_-]{0,20}$/.test(firstLine)) return null;
        if (!firstLine.startsWith("-----BEGIN")) inner = inner.slice(nl + 1);
    }

    const parsed = parseArmor(inner, expectKind);
    if (!parsed) return null;

    const start = content.indexOf(trimmed);
    return { ...parsed, start, end: start + trimmed.length };
}

/**
 * A detached-signed message (the plain text followed by a PGP SIGNATURE block, fenced or bare) as older DiscordPG
 * versions sent them. Anyone can read the text; DiscordPG verifies the trailing signature over it. Returns null unless the content ends
 * with a well-formed signature block preceded by non-empty text.
 */
export function extractDetachedSigned(content: string): { text: string; signature: string } | null {
    if (typeof content !== "string" || content.length > ARMOR_MAX_BYTES + SIGN_TEXT_MAX_CHARS) return null;
    const sigAt = content.lastIndexOf(BEGIN("SIGNATURE"));
    if (sigAt <= 0) return null;
    let cut = sigAt;
    // Optional opening fence ("```" or "```asc") on the line before the BEGIN line.
    const head = content.slice(0, sigAt);
    const fenceAt = head.lastIndexOf("```");
    if (fenceAt !== -1 && /^```[A-Za-z0-9_-]{0,20}\r?\n$/.test(head.slice(fenceAt))) cut = fenceAt;
    const text = content.slice(0, cut).trim();
    if (!text || text.length > SIGN_TEXT_MAX_CHARS) return null;
    const block = extractArmor(content.slice(cut), "SIGNATURE");
    return block ? { text, signature: block.armored } : null;
}

export const isEncryptedMessage = (content: string) => extractArmor(content, "MESSAGE") !== null;
export const isClearsignedMessage = (content: string) => extractArmor(content, "SIGNED MESSAGE") !== null;
export const isPublicKeyBlock = (content: string) => extractArmor(content, "PUBLIC KEY BLOCK") !== null;

/** Wrap canonical armor for sending through Discord. */
export function wrapForDiscord(armored: string, codeBlock: boolean): string {
    const body = armored.endsWith("\n") ? armored.slice(0, -1) : armored;
    return codeBlock ? "```\n" + body + "\n```" : body;
}

/** Discord's content limit for the current user. premiumType 2 = Nitro (not Basic). */
export function discordContentLimit(premiumType: number | null | undefined): number {
    return premiumType === 2 ? 4000 : 2000;
}

/** Cheap, stable content hash for cache invalidation (not a security primitive). */
export function fnv1a64(s: string): string {
    let h = 0xcbf29ce484222325n;
    const prime = 0x100000001b3n;
    for (let i = 0; i < s.length; i++) {
        h ^= BigInt(s.charCodeAt(i));
        h = (h * prime) & 0xffffffffffffffffn;
    }
    return h.toString(16).padStart(16, "0");
}
