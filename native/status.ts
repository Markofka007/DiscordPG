/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Parser for gpg's machine-readable `--status-fd` protocol (see doc/DETAILS in
 * the GnuPG source). Pure functions; no I/O.
 */

import { CHANNEL_NOTATION, DecryptSuccess, ErrorCode, FINGERPRINT_RE, SignatureInfo } from "../core/types";

export interface StatusEvent {
    keyword: string;
    args: string[];
    /** Everything after the keyword, unsplit (user IDs in GOODSIG contain spaces). */
    rest: string;
}

const PREFIX = "[GNUPG:] ";

export function parseStatusLines(stderr: string): StatusEvent[] {
    const out: StatusEvent[] = [];
    for (const raw of stderr.split(/\r?\n/)) {
        if (!raw.startsWith(PREFIX)) continue;
        const line = raw.slice(PREFIX.length).trimEnd();
        const sp = line.indexOf(" ");
        const keyword = sp === -1 ? line : line.slice(0, sp);
        const rest = sp === -1 ? "" : line.slice(sp + 1);
        out.push({ keyword, args: rest === "" ? [] : rest.split(" "), rest });
    }
    return out;
}

/** libgpg-error packs (source << 24) | code. We only care about the code. */
export const gpgErrCode = (n: number) => n & 0xffff;

// Subset of gpg-error codes we map to UI states.
export const GPG_ERR = {
    GENERAL: 1,
    BAD_PASSPHRASE: 11,
    NO_SECKEY: 17,
    TIMEOUT: 62,
    FULLY_CANCELED: 98,
    CANCELED: 99,
    CARD: 100,
    CARD_RESET: 101,
    CARD_REMOVED: 102,
    INV_CARD: 103,
    CARD_NOT_PRESENT: 104,
    NO_SCDAEMON: 111,
    SCDAEMON: 112,
    CARD_NOT_INITIALIZED: 115,
    NO_DATA: 58,
} as const;

export function classifyErrCode(code: number): ErrorCode | null {
    switch (gpgErrCode(code)) {
        case GPG_ERR.NO_SECKEY: return "not-for-you";
        case GPG_ERR.BAD_PASSPHRASE:
        case GPG_ERR.CANCELED:
        case GPG_ERR.FULLY_CANCELED: return "pin-cancelled";
        case GPG_ERR.CARD:
        case GPG_ERR.CARD_RESET:
        case GPG_ERR.CARD_REMOVED:
        case GPG_ERR.INV_CARD:
        case GPG_ERR.CARD_NOT_PRESENT:
        case GPG_ERR.NO_SCDAEMON:
        case GPG_ERR.SCDAEMON:
        case GPG_ERR.CARD_NOT_INITIALIZED: return "card-missing";
        case GPG_ERR.TIMEOUT: return "timeout";
        default: return null;
    }
}

export interface RunOutcome {
    exitCode: number | null;
    signal: string | null;
    timedOut: boolean;
    stdout: string;
    /** Raw stdout; present for binary runs (attachments). */
    stdoutBytes?: Buffer;
    stderr: string;
}

/**
 * Walk the status events of any gpg run and derive the most specific error we can.
 * Returns null when nothing indicates failure (the caller must still check the exit code).
 */
export function findFailure(events: StatusEvent[]): { error: ErrorCode; detail: string } | null {
    let sawPinentry = false;
    let cardProblem = false;
    const codes: number[] = [];

    for (const e of events) {
        switch (e.keyword) {
            case "PINENTRY_LAUNCHED": sawPinentry = true; break;
            case "CARDCTRL": {
                // 1=request insertion 2=request removal 3=card with serial inserted 4=no card available 5=no reader 6=no card support 7=card is in termination state 8=app not supported
                const what = Number(e.args[0]);
                if (what === 1 || what === 4 || what === 5 || what === 6 || what === 7) cardProblem = true;
                break;
            }
            case "SC_OP_FAILURE": cardProblem = true; break;
            case "ERROR":
            case "FAILURE": {
                const n = Number(e.args[1]);
                if (Number.isFinite(n)) codes.push(n);
                break;
            }
            case "INV_RECP":
            case "INV_SGNR":
                return { error: "invalid-recipient", detail: `gpg rejected key (reason ${e.args[0]})` };
            case "KEYEXPIRED": return { error: "key-expired", detail: "a key involved has expired" };
            case "KEYREVOKED": return { error: "key-revoked", detail: "a key involved has been revoked" };
            case "BADSIG": return { error: "tampered", detail: "signature verification failed" };
            case "BADMDC": return { error: "tampered", detail: "integrity check failed" };
            case "DECRYPTION_FAILED": {
                const specific = codes.map(classifyErrCode).find(Boolean);
                if (specific) return { error: specific, detail: "decryption failed" };
                if (cardProblem) return { error: "card-missing", detail: "smartcard not available" };
                return { error: "tampered", detail: "decryption failed" };
            }
        }
    }

    for (const c of codes) {
        const specific = classifyErrCode(c);
        if (specific) return { error: specific, detail: `gpg error code ${gpgErrCode(c)}` };
    }
    if (cardProblem) return { error: "card-missing", detail: "smartcard not available" };
    if (codes.length) return { error: "gpg-error", detail: `gpg error code ${gpgErrCode(codes[0])}${sawPinentry ? " (after pinentry)" : ""}` };
    return null;
}

/** gpg percent-escapes status data (%25, %0A …). */
export const unescapeStatus = (s: string) => s.replace(/%([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));

export function extractSignature(events: StatusEvent[]): SignatureInfo {
    let sigCount = 0;
    let info: SignatureInfo = { status: "none" };
    let pendingGood: "good" | "good-expired-key" | "good-revoked-key" | null = null;
    const notations: Record<string, string> = {};
    let notation: string | null = null;

    for (const e of events) {
        switch (e.keyword) {
            case "NEWSIG": sigCount++; break;
            case "NOTATION_NAME": notation = e.rest; notations[notation] = ""; break;
            case "NOTATION_DATA": if (notation) notations[notation] += unescapeStatus(e.rest); break;
            case "GOODSIG": pendingGood = "good"; break;
            case "EXPKEYSIG": pendingGood = "good-expired-key"; break;
            case "REVKEYSIG": pendingGood = "good-revoked-key"; break;
            case "EXPSIG": pendingGood = "good-expired-key"; break; // signature itself expired: treat conservatively
            case "BADSIG": return { status: "bad" };
            case "ERRSIG": {
                // ERRSIG <keyid> <pkalgo> <hashalgo> <sigclass> <time> <rc> [<fpr>]
                return { status: "unknown-key", keyId: e.args[0] ?? "" };
            }
            case "VALIDSIG": {
                // VALIDSIG <fpr> <date> <timestamp> <expire> <version> <reserved> <pkalgo> <hashalgo> <sigclass> [<primary-fpr>]
                const fpr = (e.args[0] ?? "").toUpperCase();
                const primary = (e.args[9] ?? fpr).toUpperCase();
                const ts = Number(e.args[2]);
                if (!FINGERPRINT_RE.test(fpr) || !FINGERPRINT_RE.test(primary)) return { status: "bad" };
                if (info.status === "none" && pendingGood) {
                    info = { status: pendingGood, fingerprint: fpr, primaryFingerprint: primary, timestamp: Number.isFinite(ts) ? ts : 0 };
                }
                pendingGood = null;
                break;
            }
        }
    }
    // A message carrying several signatures is not something we ever produce; refuse to vouch for it.
    if (sigCount > 1) return { status: "bad" };
    if (info.status !== "none" && info.status !== "bad" && info.status !== "unknown-key" && Object.keys(notations).length) info.notations = notations;
    return info;
}

/** Does the signature's channel notation name a different channel than the one it was received in? */
export function channelMismatch(sig: SignatureInfo, channelId: string | null | undefined): boolean {
    if (!channelId || !("notations" in sig) || !sig.notations) return false;
    const n = sig.notations[CHANNEL_NOTATION];
    return n !== undefined && n !== channelId;
}

/** gpg exits 2 when a signature could not be checked (unknown key); that is a verdict, not a failure. */
const exitAcceptable = (run: RunOutcome, events: StatusEvent[]) =>
    run.exitCode === 0 || (run.exitCode === 2 && events.some(e => e.keyword === "ERRSIG"));

/**
 * `gpg --decrypt` output for either an encrypted message or a signed-only block (encoded / clearsigned):
 * gpg handles both, and `mode` tells the caller which it was.
 */
export function interpretDecrypt(run: RunOutcome): { ok: true; value: Omit<DecryptSuccess, "verdict"> } | { ok: false; error: ErrorCode; detail: string } {
    const events = parseStatusLines(run.stderr);
    if (run.timedOut) return { ok: false, error: "timeout", detail: "gpg did not finish in time" };

    const failure = findFailure(events);
    if (failure) return { ok: false, ...failure };

    const noData = events.some(e => e.keyword === "NODATA");
    const encrypted = events.some(e => e.keyword === "ENC_TO" || e.keyword === "BEGIN_DECRYPTION");
    const okay = events.some(e => e.keyword === "DECRYPTION_OKAY");
    if (encrypted && (!okay || noData || !exitAcceptable(run, events))) {
        if (events.some(e => e.keyword === "NO_SECKEY") && !events.some(e => e.keyword === "DECRYPTION_KEY"))
            return { ok: false, error: "not-for-you", detail: "not encrypted to any of your keys" };
        return { ok: false, error: noData ? "malformed" : "tampered", detail: `gpg exit ${run.exitCode ?? run.signal}` };
    }
    if (!encrypted && (noData || !exitAcceptable(run, events))) {
        return { ok: false, error: noData ? "malformed" : "tampered", detail: `gpg exit ${run.exitCode ?? run.signal}` };
    }

    const signature = extractSignature(events);
    if (signature.status === "bad") return { ok: false, error: "tampered", detail: "signature verification failed" };
    if (!encrypted && signature.status === "none") return { ok: false, error: "malformed", detail: "neither encrypted nor signed" };

    const encryptedTo = events.filter(e => e.keyword === "ENC_TO").map(e => e.args[0].toUpperCase());
    const plaintext = encrypted ? run.stdout : run.stdout.replace(/\r\n/g, "\n"); // textmode output uses native EOLs
    return { ok: true, value: { plaintext, signature, encryptedTo, mode: encrypted ? "encrypted" : "signed" } };
}

/** `gpg --decrypt` on a block that must NOT be encrypted (the verify IPC is not a second decrypt path). */
export function interpretVerify(run: RunOutcome): ReturnType<typeof interpretDecrypt> {
    const r = interpretDecrypt(run);
    if (r.ok && r.value.mode !== "signed") return { ok: false, error: "malformed", detail: "verify called on encrypted data" };
    return r;
}

/** `gpg --verify <sig> -`: no output, only a verdict. */
export function interpretDetachedVerify(run: RunOutcome): { ok: true; signature: SignatureInfo } | { ok: false; error: ErrorCode; detail: string } {
    const events = parseStatusLines(run.stderr);
    if (run.timedOut) return { ok: false, error: "timeout", detail: "gpg did not finish in time" };
    const failure = findFailure(events);
    if (failure) return { ok: false, ...failure };
    if (events.some(e => e.keyword === "NODATA")) return { ok: false, error: "malformed", detail: "not a signature" };
    if (!exitAcceptable(run, events)) return { ok: false, error: "tampered", detail: `gpg exit ${run.exitCode ?? run.signal}` };
    const signature = extractSignature(events);
    if (signature.status === "bad") return { ok: false, error: "tampered", detail: "signature verification failed" };
    if (signature.status === "none") return { ok: false, error: "malformed", detail: "no signature found" };
    return { ok: true, signature };
}

export function interpretSign(run: RunOutcome): { ok: true } | { ok: false; error: ErrorCode; detail: string } {
    const events = parseStatusLines(run.stderr);
    if (run.timedOut) return { ok: false, error: "timeout", detail: "gpg did not finish in time" };
    const failure = findFailure(events);
    if (failure) return { ok: false, ...failure };
    if (run.exitCode !== 0 || !events.some(e => e.keyword === "SIG_CREATED")) return { ok: false, error: "gpg-error", detail: `gpg did not sign (exit ${run.exitCode ?? run.signal})` };
    return { ok: true };
}

/**
 * `expectedKeys`: the primary fingerprints we asked gpg to use (recipients + signer). gpg reports the primary
 * key of every keyblock it looked up as KEY_CONSIDERED; if it considered any other key, a fingerprint resolved
 * to a different keyblock than the one it names (see GpgService.resolveExact) and the output must not be used.
 */
export function interpretEncrypt(run: RunOutcome, expectSigned: boolean, armored = true, expectedKeys?: readonly string[]): { ok: true; signed: boolean } | { ok: false; error: ErrorCode; detail: string } {
    const events = parseStatusLines(run.stderr);
    if (run.timedOut) return { ok: false, error: "timeout", detail: "gpg did not finish in time" };
    if (expectedKeys) {
        const stray = events.filter(e => e.keyword === "KEY_CONSIDERED").map(e => (e.args[0] ?? "").toUpperCase()).find(f => !expectedKeys.includes(f));
        if (stray !== undefined) return { ok: false, error: "ambiguous-key", detail: `gpg used key ${stray || "(unknown)"}, which is not one of the requested keys` };
    }
    const failure = findFailure(events);
    if (failure) return { ok: false, ...failure };
    const ended = events.some(e => e.keyword === "END_ENCRYPTION");
    const signed = events.some(e => e.keyword === "SIG_CREATED");
    if (!ended || run.exitCode !== 0) return { ok: false, error: "gpg-error", detail: `gpg exit ${run.exitCode ?? run.signal}` };
    if (expectSigned && !signed) return { ok: false, error: "gpg-error", detail: "gpg did not sign" };
    if (armored && !run.stdout.startsWith("-----BEGIN PGP MESSAGE-----")) return { ok: false, error: "gpg-error", detail: "unexpected gpg output" };
    if (!armored && !(run.stdoutBytes && run.stdoutBytes.length > 0)) return { ok: false, error: "gpg-error", detail: "gpg produced no output" };
    return { ok: true, signed };
}

/**
 * `gpg --import-options show-only --with-colons --import`: lists what an import WOULD do without touching the
 * keyring. gpg imports by packet type, not by armor label, so a secret key inside a "PUBLIC KEY BLOCK" would
 * land in the secret keyring; the real import therefore only runs if this listing shows public keys and nothing else.
 */
export function interpretImportPreview(run: RunOutcome): { ok: true } | { ok: false; error: ErrorCode; detail: string } {
    if (run.timedOut) return { ok: false, error: "timeout", detail: "gpg did not finish in time" };
    const records = run.stdout.split(/\r?\n/).map(l => l.split(":")[0]);
    if (records.some(t => t === "sec" || t === "ssb")) return { ok: false, error: "secret-key-block", detail: "block contained secret key material" };
    if (run.exitCode !== 0 || !records.includes("pub")) return { ok: false, error: "malformed", detail: `no public key found in the block (gpg exit ${run.exitCode ?? run.signal})` };
    return { ok: true };
}

export function interpretImport(run: RunOutcome): { ok: true; fingerprints: string[] } | { ok: false; error: ErrorCode; detail: string } {
    const events = parseStatusLines(run.stderr);
    if (run.timedOut) return { ok: false, error: "timeout", detail: "gpg did not finish in time" };
    const failure = findFailure(events);
    if (failure) return { ok: false, ...failure };
    const fprs = events.filter(e => e.keyword === "IMPORT_OK").map(e => e.args[1]?.toUpperCase()).filter(f => FINGERPRINT_RE.test(f));
    // IMPORT_RES <count> <no_user_id> <imported> <reserved> <unchanged> <n_uids> <n_subk> <n_sigs> <n_revoc> <sec_read> <sec_imported> <sec_dups> <skipped_new_keys> <not_imported> <skipped_v3_keys>
    const res = events.find(e => e.keyword === "IMPORT_RES");
    if (res && Number(res.args[9]) > 0) return { ok: false, error: "secret-key-block", detail: "block contained secret key material" };
    if (run.exitCode !== 0 || fprs.length === 0) return { ok: false, error: "malformed", detail: "no keys imported" };
    return { ok: true, fingerprints: [...new Set(fprs)] };
}
