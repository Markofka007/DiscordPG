/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/** Renderer-side CryptoBackend that forwards to the main process over Vencord's plugin IPC. */

import { PluginNative } from "@utils/types";

import { AttachmentDecryptResult, AttachmentEncryptResult, BackendStatus, Binding, CryptoBackend, DecryptResult, EncryptResult, ErrorCode, fail, Fingerprint, ImportResult, KeyInfo, NATIVE_API_VERSION, Result, SignResult, Snowflake, VerifyResult } from "./types";

export const Native = VencordNative.pluginHelpers.DiscordPG as PluginNative<typeof import("../native")>;

/** IPC failures (plugin disabled mid-call, main process threw) must never surface as a thrown exception in the send path. */
async function safe<T>(p: Promise<Result<T>>): Promise<Result<T>> {
    try {
        return await p;
    } catch (e) {
        return fail("gpg-error", "IPC call failed");
    }
}

/** "ok" when the main process runs the same DiscordPG build as this renderer; otherwise why not. */
export async function checkNativeVersion(): Promise<"ok" | "stale"> {
    try {
        return (await Native.apiVersion()) === NATIVE_API_VERSION ? "ok" : "stale";
    } catch {
        return "stale"; // older builds do not export apiVersion at all
    }
}

export const gpgBackend: CryptoBackend = {
    status: () => Native.status(),
    listSecretKeys: () => safe(Native.listSecretKeys()),
    exportPublicKey: (fpr: Fingerprint) => safe(Native.exportPublicKey(fpr)),
    importPublicKey: (armored: string): Promise<ImportResult> => safe(Native.importPublicKey(armored)),
    encryptAndSign: (req): Promise<EncryptResult> => safe(Native.encryptAndSign(req)),
    decrypt: (req): Promise<DecryptResult> => safe(Native.decrypt(req)),
    sign: (req): Promise<SignResult> => safe(Native.sign(req)),
    verify: (req): Promise<VerifyResult> => safe(Native.verify(req)),
    encryptAttachment: (req): Promise<AttachmentEncryptResult> => safe(Native.encryptAttachment(req)),
    decryptAttachment: (req): Promise<AttachmentDecryptResult> => safe(Native.decryptAttachment(req)),
    fetchArmored: (req): Promise<Result<{ text: string }>> => safe(Native.fetchArmored(req)),
    lock: async () => { await safe(Native.lock()); },
};

export const bindingsApi = {
    getAll: (): Promise<Result<{ bindings: Binding[] }>> => safe(Native.getBindings()),
    bind: (userId: Snowflake, fingerprint: Fingerprint, userLabel: string) => safe(Native.bindKey({ userId, fingerprint, userLabel })),
    verify: (userId: Snowflake, fingerprint: Fingerprint, userLabel: string) => safe(Native.setVerified({ userId, fingerprint, userLabel })),
    unbind: (userId: Snowflake, fingerprint: Fingerprint, userLabel: string) => safe(Native.unbindKey({ userId, fingerprint, userLabel })),
};

export type { BackendStatus, KeyInfo };

/** Short, user-facing explanation per error code. Never includes message content. */
export function describeError(code: ErrorCode, detail?: string): string {
    switch (code) {
        case "not-for-you": return "This message is not encrypted to any of your keys.";
        case "card-missing": return "Your YubiKey / smartcard is not available. Insert it and retry.";
        case "pin-cancelled": return "PIN entry was cancelled or the PIN was wrong.";
        case "timeout": return "gpg did not respond in time (PIN prompt or touch left pending?).";
        case "gpg-missing": return "gpg was not found. Install GnuPG or set the path in DiscordPG settings.";
        case "tampered": return "Decryption or signature verification failed. The message may have been altered.";
        case "oversize": return "The content is too large.";
        case "malformed": return "This is not a valid PGP block.";
        case "no-own-key": return "No usable secret key is configured. Pick your key in DiscordPG settings.";
        case "key-revoked": return "The key has been revoked.";
        case "key-expired": return "The key has expired.";
        case "invalid-recipient": return "The recipient key is not trusted. Bind it to the user first.";
        case "ambiguous-key": return `A key fingerprint does not resolve to the key it names${detail ? ` (${detail})` : ""}. Another key in your keyring carries the same fingerprint as a subkey, so gpg could encrypt to the wrong person; nothing was encrypted. Remove the impostor key with gpg --delete-keys, then try again.`;
        case "secret-key-block": return "That block contains a private key. DiscordPG only imports public keys.";
        case "download-failed": return `Could not download the attachment${detail ? ` (${detail})` : ""}.`;
        case "cancelled": return "Cancelled.";
        case "invalid-args": return `Internal validation error${detail ? `: ${detail}` : ""}.`;
        case "gpg-error": return `gpg failed${detail ? ` (${detail})` : ""}.`;
    }
}
