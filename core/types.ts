/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Shared, dependency-free types. Imported by both the renderer plugin and the
 * Electron main-process (native/) side, so nothing in here may import Vencord,
 * Electron, Node or DOM APIs.
 */

/** 40 uppercase hex characters. The only key identifier used anywhere in DiscordPG. */
export type Fingerprint = string;

/** Discord snowflake as a decimal string. */
export type Snowflake = string;

export const FINGERPRINT_RE = /^[0-9A-F]{40}$/;
export const SNOWFLAKE_RE = /^[0-9]{17,20}$/;

/** Hard cap on any armored block we are willing to look at, in bytes. */
export const ARMOR_MAX_BYTES = 64 * 1024;
/** Hard cap on plaintext we are willing to encrypt (Discord's own limit is far lower). */
export const PLAINTEXT_MAX_BYTES = 64 * 1024;
/** `gpg --max-output`: cap on decrypted output to defuse decompression bombs. */
export const DECRYPT_MAX_OUTPUT_BYTES = 1024 * 1024;
/**
 * Bumped whenever the renderer<->main contract changes. The renderer compares it with what the
 * running main process reports: Ctrl+R reloads the renderer only, so after a rebuild the main
 * process keeps the old native/ code until Discord is fully restarted.
 */
export const NATIVE_API_VERSION = 6;
/** Hard cap on an attachment we encrypt or decrypt (input side). Discord's own limits are lower for most users. */
export const ATTACHMENT_MAX_BYTES = 64 * 1024 * 1024;
/** `gpg --max-output` for attachments. */
export const ATTACHMENT_DECRYPT_MAX_OUTPUT_BYTES = 64 * 1024 * 1024;
/** Largest decrypted image we hand back to the renderer for an inline preview. */
export const PREVIEW_MAX_BYTES = 32 * 1024 * 1024;
/**
 * Attachment downloads happen in the main process (the renderer's fetch is blocked by Discord's CORS/CSP
 * rules for the CDN, and the save path must never see plaintext). The renderer supplies the URL, so the
 * main process only ever downloads from Discord's attachment CDNs, over https, under /attachments/.
 */
export const ATTACHMENT_URL_HOSTS: readonly string[] = ["cdn.discordapp.com", "media.discordapp.net", "cdn-b1.discordapp.com", "cdn-b2.discordapp.com", "media-b1.discordapp.net", "media-b2.discordapp.net"];
export const ATTACHMENT_URL_PATH_RE = /^\/(?:ephemeral-)?attachments\/\d{1,20}\/\d{1,20}\/[^/]+$/;
/** Longest text we are willing to sign without encrypting (Discord's Nitro message limit). */
export const SIGN_TEXT_MAX_CHARS = 4000;
/** Sign-only is a signing oracle for renderer code; keep it slow. */
export const SIGN_RATE_LIMIT = { max: 10, perMs: 60_000 };
/** Signature notation naming the Discord channel a sign-only message was written for (replay detection). */
export const CHANNEL_NOTATION = "channel@discordpg.invalid";

/** How an unencrypted message is signed. Encrypted messages always carry the signature inside the PGP block. */
/** Most recipients one message may be encrypted to: a full group DM (10 members) plus headroom. Discord caps group DMs at 10. */
export const MAX_RECIPIENTS = 16;

export type ErrorCode =
    | "invalid-args"      // IPC argument failed validation
    | "gpg-missing"       // gpg binary not found / not executable
    | "gpg-error"         // gpg exited abnormally with no more specific status
    | "timeout"           // gpg did not finish in time (pinentry left open, card stalled)
    | "not-for-you"       // ciphertext is not encrypted to any of our secret keys
    | "card-missing"      // smartcard required but not present
    | "pin-cancelled"     // pinentry was dismissed / wrong PIN
    | "tampered"          // integrity check failed or signature is BAD
    | "oversize"          // input exceeds a hard cap
    | "malformed"         // armor did not parse
    | "no-own-key"        // no own key configured / found
    | "key-revoked"
    | "key-expired"
    | "invalid-recipient" // gpg rejected a recipient fingerprint
    | "ambiguous-key"     // a fingerprint does not resolve to exactly the key it names (another key carries it as a subkey)
    | "secret-key-block"  // import refused because the block contains secret key material
    | "download-failed"   // the main process could not download an attachment from Discord's CDN
    | "cancelled";        // user declined a native confirmation dialog

export interface Failure {
    ok: false;
    error: ErrorCode;
    /** Human-readable, never contains plaintext, armor or key material. */
    detail?: string;
}

export type Result<T> = ({ ok: true } & T) | Failure;

export const fail = (error: ErrorCode, detail?: string): Failure => ({ ok: false, error, detail });

/** Facts gpg reported about the signature on a decrypted message. */
export interface GoodSignature {
    fingerprint: Fingerprint;
    primaryFingerprint: Fingerprint;
    timestamp: number;
    /** Signature notations (name -> data), e.g. the DiscordPG channel notation. */
    notations?: Record<string, string>;
}
export type SignatureInfo =
    | { status: "none" }
    | ({ status: "good" } & GoodSignature)
    | ({ status: "good-expired-key" } & GoodSignature)
    | ({ status: "good-revoked-key" } & GoodSignature)
    | { status: "bad" }
    | { status: "unknown-key"; keyId: string };

/**
 * What the UI should tell the user about who wrote a message. Computed on the
 * trusted (main-process) side from SignatureInfo + the author's key binding.
 */
export type SigVerdict =
    | { kind: "self"; fingerprint: Fingerprint }                // our own message, signed by one of our secret keys
    | { kind: "verified"; fingerprint: Fingerprint }            // signed by the author's bound key; binding marked verified
    | { kind: "unverified-contact"; fingerprint: Fingerprint }  // signed by the author's bound key; binding not yet verified
    | { kind: "mismatch"; fingerprint: Fingerprint; expected: Fingerprint | null } // signed by some other key
    | { kind: "unknown-signer"; keyId: string }                 // signed, but we do not have the public key
    | { kind: "bad" }                                           // signature present but invalid: treat as tampered
    | { kind: "unsigned" };

export interface DecryptSuccess {
    plaintext: string;
    signature: SignatureInfo;
    verdict: SigVerdict;
    /** Long key IDs (16 hex) the session key was encrypted to, as reported by ENC_TO. Informational only. */
    encryptedTo: string[];
    /** "signed": the block was signed but not encrypted (sign-only styles). */
    mode: "encrypted" | "signed";
    /** The signature's channel notation names a different Discord channel: likely copied from elsewhere. */
    channelMismatch?: boolean;
}
export type DecryptResult = Result<DecryptSuccess>;

export type SignResult = Result<{ armored: string }>;
export type VerifyRequest = { channelId: Snowflake | null; authorUserId: Snowflake | null; authorIsSelf?: boolean } & (
    | { kind: "clearsign" | "encoded"; armored: string }
    | { kind: "detached"; text: string; signature: string }
);
export type VerifyResult = Result<DecryptSuccess>;

export interface EncryptSuccess {
    armored: string;
    signed: boolean;
}
export type EncryptResult = Result<EncryptSuccess>;

/** Binary OpenPGP message (what goes into a `.gpg` attachment). */
export type AttachmentEncryptResult = Result<{ data: Uint8Array; signed: boolean }>;

export type AttachmentAction = "preview" | "save";
export type AttachmentDecryptSuccess = {
    signature: SignatureInfo;
    verdict: SigVerdict;
    /** Decrypted size in bytes. */
    size: number;
} & (
    | { action: "preview"; data: Uint8Array; mime: string }   // only for images, only on request
    | { action: "save"; savedTo: string }                      // written by the main process; bytes never reach the renderer
);
export type AttachmentDecryptResult = Result<AttachmentDecryptSuccess>;

export interface KeyUserId {
    uid: string;
    validity: string;
}

export interface KeyInfo {
    fingerprint: Fingerprint;
    /** Public-key algorithm number (RFC 4880 / 9580): 1=RSA, 18=ECDH, 19=ECDSA, 22=EdDSA, 25=X25519, 27=Ed25519 … */
    algo: number;
    algoName: string;
    curve: string | null;
    bits: number;
    created: number;
    expires: number | null;
    revoked: boolean;
    expired: boolean;
    disabled: boolean;
    /** Capability letters: e=encrypt s=sign c=certify a=auth */
    capabilities: string;
    /** Smartcard serial if the secret key lives on a card, "+" if on disk, "#" if stub/offline. */
    cardSerial: string | null;
    uids: KeyUserId[];
    subkeys: Array<{
        fingerprint: Fingerprint;
        algo: number;
        algoName: string;
        curve: string | null;
        bits: number;
        capabilities: string;
        expires: number | null;
        revoked: boolean;
        expired: boolean;
        cardSerial: string | null;
    }>;
}

export interface ImportSuccess {
    /** Primary fingerprints of keys that were imported or already present. */
    fingerprints: Fingerprint[];
    keys: KeyInfo[];
}
export type ImportResult = Result<ImportSuccess>;

export interface Binding {
    userId: Snowflake;
    fingerprint: Fingerprint;
    verified: boolean;
    addedAt: number;
    changedAt: number | null;
    previousFingerprints: Fingerprint[];
}

export interface BackendStatus {
    gpgPath: string | null;
    /** Why gpg could not be located / was rejected, for the settings panel. null when found. */
    gpgReason: string | null;
    gpgVersion: string | null;
    libgcryptVersion: string | null;
    agentReachable: boolean;
    cardPresent: boolean | null;
    cardSerial: string | null;
    bindingsPath: string;
    bindingsCount: number;
}

/**
 * The crypto abstraction the renderer talks to. v1 ships GpgBackend (over
 * Vencord's native IPC); an openpgp.js backend can implement the same surface later.
 */
export interface CryptoBackend {
    status(): Promise<BackendStatus>;
    listSecretKeys(): Promise<Result<{ keys: KeyInfo[] }>>;
    exportPublicKey(fingerprint: Fingerprint): Promise<Result<{ armored: string }>>;
    importPublicKey(armored: string): Promise<ImportResult>;
    encryptAndSign(req: { plaintext: string; recipients: Fingerprint[]; signWith: Fingerprint | null }): Promise<EncryptResult>;
    decrypt(req: { armored: string; authorUserId: Snowflake | null; authorIsSelf?: boolean; channelId?: Snowflake | null }): Promise<DecryptResult>;
    /** Sign without encrypting. Always clearsigned: readable text with the signature underneath. */
    sign(req: { text: string; channelId: Snowflake; signWith: Fingerprint }): Promise<SignResult>;
    verify(req: VerifyRequest): Promise<VerifyResult>;
    encryptAttachment(req: { data: Uint8Array; filename: string; recipients: Fingerprint[]; signWith: Fingerprint | null }): Promise<AttachmentEncryptResult>;
    /** `url` must be a Discord CDN attachment URL; the main process downloads it (see ATTACHMENT_URL_HOSTS). */
    decryptAttachment(req: { url: string; filename: string; authorUserId: Snowflake | null; authorIsSelf?: boolean; action: AttachmentAction }): Promise<AttachmentDecryptResult>;
    /** Download a small text attachment that must be ASCII armor (public key, message, signature). */
    fetchArmored(req: { url: string }): Promise<Result<{ text: string }>>;
    lock(): Promise<void>;
}
