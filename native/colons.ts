/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/** Parser for `gpg --with-colons --with-fingerprint` key listings (doc/DETAILS "Format of the colon listings"). */

import { FINGERPRINT_RE, KeyInfo } from "../core/types";

const ALGO_NAMES: Record<number, string> = {
    1: "RSA", 2: "RSA-E", 3: "RSA-S", 16: "ElGamal", 17: "DSA", 18: "ECDH", 19: "ECDSA",
    22: "EdDSA", 25: "X25519", 27: "Ed25519", 28: "X448", 29: "Ed448",
};
export const algoName = (n: number) => ALGO_NAMES[n] ?? `algo${n}`;

/** gpg C-escapes colons and non-printables in uid fields as \xNN. */
export function unescapeColonField(s: string): string {
    return s.replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

const num = (s: string) => (s === "" ? null : Number(s));

export function parseKeyListing(text: string): KeyInfo[] {
    const keys: KeyInfo[] = [];
    let cur: KeyInfo | null = null;
    let lastKind: "primary" | "sub" | "other" = "other";

    for (const line of text.split(/\r?\n/)) {
        if (!line) continue;
        const f = line.split(":");
        const type = f[0];
        if (type === "pub" || type === "sec") {
            const algo = Number(f[3]);
            cur = {
                fingerprint: "",
                algo,
                algoName: algoName(algo),
                curve: f[16] || null,
                bits: Number(f[2]) || 0,
                created: Number(f[5]) || 0,
                expires: num(f[6]),
                revoked: f[1] === "r",
                expired: f[1] === "e",
                disabled: (f[11] ?? "").includes("D") || f[1] === "d",
                capabilities: (f[11] ?? "").replace(/[A-Z]/g, ""),
                cardSerial: type === "sec" ? cardSerialOf(f[14]) : null,
                uids: [],
                subkeys: [],
            };
            keys.push(cur);
            lastKind = "primary";
        } else if ((type === "sub" || type === "ssb") && cur) {
            const algo = Number(f[3]);
            cur.subkeys.push({
                fingerprint: "",
                algo,
                algoName: algoName(algo),
                curve: f[16] || null,
                bits: Number(f[2]) || 0,
                capabilities: (f[11] ?? "").replace(/[A-Z]/g, ""),
                expires: num(f[6]),
                revoked: f[1] === "r",
                expired: f[1] === "e",
                cardSerial: type === "ssb" ? cardSerialOf(f[14]) : null,
            });
            lastKind = "sub";
        } else if (type === "fpr" && cur) {
            const fpr = (f[9] ?? "").toUpperCase();
            if (!FINGERPRINT_RE.test(fpr)) continue;
            if (lastKind === "primary" && !cur.fingerprint) cur.fingerprint = fpr;
            else if (lastKind === "sub") {
                const sk = cur.subkeys[cur.subkeys.length - 1];
                if (sk && !sk.fingerprint) sk.fingerprint = fpr;
            }
        } else if (type === "uid" && cur) {
            cur.uids.push({ uid: unescapeColonField(f[9] ?? ""), validity: f[1] ?? "" });
        }
        // tru, grp, rvk, sig etc. are ignored
    }
    return keys.filter(k => k.fingerprint);
}

/** Field 15 of sec/ssb: "+" on disk, "#" stub (offline), otherwise a token serial number. */
function cardSerialOf(field: string | undefined): string | null {
    if (!field || field === "+" || field === "#") return field === "#" ? "#" : field === "+" ? "+" : null;
    return field;
}

/** True if any subkey (or the primary) with the given capability lives on a smartcard. */
export function usesCard(key: KeyInfo, capability: "e" | "s"): boolean {
    const parts = [key, ...key.subkeys];
    return parts.some(p => p.capabilities.includes(capability) && p.cardSerial != null && p.cardSerial !== "+" && p.cardSerial !== "#");
}

export function canEncryptTo(key: KeyInfo): boolean {
    if (key.revoked || key.expired || key.disabled) return false;
    const now = Math.floor(Date.now() / 1000);
    return [key, ...key.subkeys].some(p => p.capabilities.includes("e") && !p.revoked && !p.expired && (p.expires == null || p.expires > now));
}

/** RSA keys produce ~520-byte session-key packets per recipient; warn, since two of them plus a signature blow Discord's 2000-char limit. */
export function isLargeAlgo(key: KeyInfo): boolean {
    return [key, ...key.subkeys].some(p => p.capabilities.includes("e") && (p.algo === 1 || p.algo === 2 || p.algo === 16));
}
