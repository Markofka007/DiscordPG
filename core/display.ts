/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/** Pure display-state helpers shared by the renderer store and the tests. */

import { DecryptSuccess, ErrorCode, SigVerdict } from "./types";

export type DecryptEntry =
    | { state: "idle" }                                   // armored, but not (yet) decrypting (manual / newOnly policy)
    | { state: "pending" }
    | ({ state: "ok" } & DecryptSuccess)
    | { state: "error"; error: ErrorCode; detail?: string };

/**
 * Should Discord's own rendering of the ciphertext be hidden? Yes while we show plaintext and while we are
 * decrypting (the accessory shows a "Decrypting…" banner in its place). Idle (manual mode) and error states
 * keep the armor visible so the user can see what we could not handle.
 */
export function hiddenFor(entry: DecryptEntry, showOriginal: boolean): boolean {
    return !showOriginal && (entry.state === "ok" || entry.state === "pending");
}

const group = (f: string) => f.replace(/(.{4})/g, "$1 ").trim();

/**
 * Plain-text warning for verdicts that do not vouch for the sender, or null when the verdict is fine.
 * Used by the main process for OS dialogs (it cannot use the React verdict views).
 */
export function verdictWarning(v: SigVerdict): string | null {
    switch (v.kind) {
        case "self":
        case "verified":
        case "unverified-contact":
            return null;
        case "mismatch":
            return `Signed by ${group(v.fingerprint)}, which is NOT the key bound to the sender${v.expected ? ` (${group(v.expected)})` : ""}.`;
        case "unknown-signer":
            return `Signed by key ${v.keyId}, which is not in your keyring, so the signature could not be checked.`;
        case "bad":
            return "The signature does not verify. The content may have been altered.";
        case "unsigned":
            return "The content is encrypted but not signed, so anyone with the recipients' public keys could have produced it.";
    }
}

/** Is this a verdict the UI should hide content behind an explicit click for? */
export function verdictGuarded(v: SigVerdict): boolean {
    return verdictWarning(v) !== null;
}
