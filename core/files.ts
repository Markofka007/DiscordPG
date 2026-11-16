/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/** Pure helpers for attachment names and bytes. Shared by renderer, main process and tests. */

export const PGP_FILE_RE = /\.(gpg|pgp|asc)$/i;
export const isPgpFileName = (name: string) => PGP_FILE_RE.test(name);
/** "photo.png.gpg" -> "photo.png" */
export const strippedName = (name: string) => name.replace(PGP_FILE_RE, "") || "attachment";
/** Extension we use for outgoing encrypted attachments (binary OpenPGP). */
export const ENCRYPTED_EXT = ".gpg";
export const ENCRYPTED_MIME = "application/pgp-encrypted";
/**
 * Small text files that may turn out to be a PGP block: .asc (keys, messages) and .txt (Discord turns an
 * over-long message, e.g. a pasted public key, into a message.txt attachment). These are probed on sight.
 */
export const PROBE_FILE_RE = /\.(asc|txt)$/i;
export const isProbeFileName = (name: string) => PROBE_FILE_RE.test(name);

const IMAGE_EXT_RE = /\.(png|jpe?g|gif|webp)$/i;
export const isImageName = (name: string) => IMAGE_EXT_RE.test(name);

/** Image type from magic bytes, or null. Only formats Chromium renders inline. */
export function sniffImage(b: Uint8Array): string | null {
    if (b.length >= 8 && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47 && b[4] === 0x0d && b[5] === 0x0a && b[6] === 0x1a && b[7] === 0x0a) return "image/png";
    if (b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "image/jpeg";
    if (b.length >= 6 && b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x38 && (b[4] === 0x37 || b[4] === 0x39) && b[5] === 0x61) return "image/gif";
    if (b.length >= 12 && b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 && b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50) return "image/webp";
    return null;
}

export function formatBytes(n: number): string {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export const ARMOR_PREFIX = "-----BEGIN PGP ";
/** Does this byte buffer start with ASCII armor (as opposed to binary OpenPGP packets)? */
export function looksArmored(b: Uint8Array): boolean {
    if (b.length < ARMOR_PREFIX.length) return false;
    for (let i = 0; i < ARMOR_PREFIX.length; i++) if (b[i] !== ARMOR_PREFIX.charCodeAt(i)) return false;
    return true;
}
