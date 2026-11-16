/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * The trusted-side implementation of the crypto operations. Plain Node (no
 * Electron) so it can be exercised end-to-end against a throwaway GNUPGHOME.
 * Everything here assumes its arguments have already passed native/schema.ts.
 */

import { mkdtemp, rm, writeFile } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";

import { verdictWarning } from "../core/display";
import { looksArmored, sniffImage } from "../core/files";
import {
    ATTACHMENT_DECRYPT_MAX_OUTPUT_BYTES, ATTACHMENT_MAX_BYTES, AttachmentAction, AttachmentDecryptResult, AttachmentEncryptResult,
    Binding, CHANNEL_NOTATION, DECRYPT_MAX_OUTPUT_BYTES, DecryptResult, EncryptResult, fail, Fingerprint, ImportResult,
    KeyInfo, PREVIEW_MAX_BYTES, Result, SignatureInfo, SignResult, SigVerdict, Snowflake, VerifyRequest, VerifyResult,
} from "../core/types";
import { parseArmor } from "../core/wire";
import { BindingStore } from "./bindings";
import { parseKeyListing } from "./colons";
import { reloadAgent, runGpg, RunOptions } from "./gpg";
import { channelMismatch, interpretDecrypt, interpretDetachedVerify, interpretEncrypt, interpretImport, interpretImportPreview, interpretSign, interpretVerify } from "./status";

export interface ServiceConfig {
    gpgPath: string;
    bindings: BindingStore;
    /** Per-operation timeout; must leave room for pinentry and a card touch. */
    timeoutMs: number;
    hideRecipientKeyIds: boolean;
    /** Tests only. */
    homedir?: string;
    /** Tests only: extra args such as loopback pinentry. */
    extraArgs?: string[];
    /**
     * Writes a decrypted attachment somewhere the user picked (Electron save dialog in production, a temp dir in
     * tests). `warning` is non-null when the signature verdict does not vouch for the sender; the implementation
     * must confirm with the user before saving. Returns the path, or null if the user cancelled.
     */
    saver?: (p: { suggestedName: string; bytes: Buffer; warning: string | null }) => Promise<string | null>;
}

/** Every key an encrypt operation is supposed to touch: the recipients plus the signer. */
const partiesOf = (req: { recipients: Fingerprint[]; signWith: Fingerprint | null }): Fingerprint[] =>
    req.signWith ? [...req.recipients, req.signWith] : req.recipients;

const toBuffer = (u: Uint8Array) => Buffer.from(u.buffer, u.byteOffset, u.byteLength);

const SECRET_KEY_CACHE_MS = 60_000;

export class GpgService {
    private secretKeys: { at: number; keys: KeyInfo[] } | null = null;

    constructor(private readonly cfg: ServiceConfig) { }

    private run(args: string[], stdin?: string | Buffer, timeoutMs = this.cfg.timeoutMs, extra: Partial<Pick<RunOptions, "binaryStdout" | "stdoutCap">> = {}) {
        return runGpg({
            gpgPath: this.cfg.gpgPath,
            homedir: this.cfg.homedir,
            args: [...(this.cfg.extraArgs ?? []), ...args],
            stdin,
            timeoutMs,
            ...extra,
        });
    }

    async listSecretKeys(force = false): Promise<Result<{ keys: KeyInfo[] }>> {
        if (!force && this.secretKeys && Date.now() - this.secretKeys.at < SECRET_KEY_CACHE_MS) {
            return { ok: true, keys: this.secretKeys.keys };
        }
        const r = await this.run(["--list-secret-keys", "--with-colons", "--with-fingerprint", "--with-fingerprint"], undefined, 20_000);
        if (r.timedOut) return fail("timeout", "listing keys timed out");
        if (r.exitCode !== 0 && r.exitCode !== 2 /* 2 = no secret keys at all */) return fail("gpg-error", `gpg exit ${r.exitCode ?? r.signal}`);
        const keys = parseKeyListing(r.stdout);
        this.secretKeys = { at: Date.now(), keys };
        return { ok: true, keys };
    }

    async listPublicKeys(fingerprints: Fingerprint[]): Promise<KeyInfo[]> {
        if (fingerprints.length === 0) return [];
        const r = await this.run(["--list-keys", "--with-colons", "--with-fingerprint", "--with-fingerprint", ...fingerprints], undefined, 20_000);
        return parseKeyListing(r.stdout);
    }

    /**
     * Each fingerprint must resolve to exactly one key in the keyring, and be that key's PRIMARY fingerprint.
     *
     * gpg matches `--recipient <fpr>` / `--local-user <fpr>` against subkeys too, and anyone can publish a key
     * that carries someone else's primary key as one of its own subkeys (no secret key needed for that). With
     * such a key in the keyring the victim's fingerprint can resolve to the impostor's keyblock, and gpg then
     * encrypts to the impostor's encryption subkey. Which keyblock wins depends on the keyring backend
     * (pubring.kbx: first imported, and both are listed; keyboxd: last imported, and only that one is listed),
     * so both conditions are checked: one match, and its primary fingerprint is the one we asked for.
     */
    async resolveExact(fingerprints: Fingerprint[]): Promise<Result<{ keys: KeyInfo[] }>> {
        const want = [...new Set(fingerprints)];
        if (want.length === 0) return { ok: true, keys: [] };
        const r = await this.run(["--list-keys", "--with-colons", "--with-fingerprint", "--with-fingerprint", ...want], undefined, 20_000);
        if (r.timedOut) return fail("timeout", "listing keys timed out");
        const listed = parseKeyListing(r.stdout);
        const keys: KeyInfo[] = [];
        for (const f of want) {
            const holders = listed.filter(k => k.fingerprint === f || k.subkeys.some(s => s.fingerprint === f));
            if (holders.length === 0) return fail("invalid-recipient", "key is not in the keyring");
            const impostor = holders.find(k => k.fingerprint !== f);
            if (impostor) return fail("ambiguous-key", `${f} is also a subkey of ${impostor.fingerprint}`);
            if (holders.length !== 1) return fail("ambiguous-key", `${f} is listed ${holders.length} times`);
            keys.push(holders[0]);
        }
        return { ok: true, keys };
    }

    private async ownFingerprints(): Promise<Set<Fingerprint>> {
        const r = await this.listSecretKeys();
        return new Set(r.ok ? r.keys.map(k => k.fingerprint) : []);
    }

    /** Fingerprints we are allowed to encrypt to or export: our own keys plus user-confirmed bindings. */
    private async allowedFingerprints(): Promise<Set<Fingerprint>> {
        const own = await this.ownFingerprints();
        for (const f of this.cfg.bindings.trustedFingerprints()) own.add(f);
        return own;
    }

    async exportPublicKey(fingerprint: Fingerprint): Promise<Result<{ armored: string }>> {
        if (!(await this.allowedFingerprints()).has(fingerprint)) return fail("invalid-recipient", "key is neither yours nor bound to a contact");
        // `--export <fpr>` matches subkeys as well; never hand out some other key under this fingerprint.
        const exact = await this.resolveExact([fingerprint]);
        if (!exact.ok) return exact;
        const r = await this.run(["--armor", "--export", fingerprint], undefined, 20_000);
        const parsed = parseArmor(r.stdout, "PUBLIC KEY BLOCK");
        if (r.exitCode !== 0 || !parsed) return fail("gpg-error", "export failed");
        return { ok: true, armored: parsed.armored };
    }

    async importPublicKey(armoredIn: string): Promise<ImportResult> {
        const parsed = parseArmor(armoredIn, "PUBLIC KEY BLOCK");
        if (!parsed) {
            if (/-----BEGIN PGP PRIVATE KEY BLOCK-----/.test(armoredIn)) return fail("secret-key-block", "refusing to import secret key material");
            return fail("malformed", "not a public key block");
        }
        // Dry run first: the armor label proves nothing about the packets inside (see interpretImportPreview).
        const preview = interpretImportPreview(await this.run(["--with-colons", "--import-options", "show-only", "--import"], parsed.armored, 30_000));
        if (!preview.ok) return preview;
        const r = await this.run(["--import", "--import-options", "no-import-local-sigs,no-repair-keys"], parsed.armored, 30_000);
        const res = interpretImport(r);
        if (!res.ok) return res;
        const keys = await this.listPublicKeys(res.fingerprints);
        return { ok: true, fingerprints: res.fingerprints, keys };
    }

    /** Recipients must be bound contacts or our own keys; the signer must be one of our secret keys. */
    private async checkEncryptParties(req: { recipients: Fingerprint[]; signWith: Fingerprint | null }): Promise<Result<{}>> {
        const allowed = await this.allowedFingerprints();
        for (const f of req.recipients) {
            if (!allowed.has(f)) return fail("invalid-recipient", "recipient is not a trusted contact or your own key");
        }
        if (req.signWith && !(await this.ownFingerprints()).has(req.signWith)) return fail("no-own-key", "signing key is not one of your secret keys");
        // Being on the allowlist is not enough: the fingerprint must also select that very key (see resolveExact).
        const exact = await this.resolveExact(partiesOf(req));
        if (!exact.ok) return exact;
        return { ok: true };
    }

    private encryptArgs(req: { recipients: Fingerprint[]; signWith: Fingerprint | null }, armor: boolean): string[] {
        const args = [...(armor ? ["--armor"] : []), "--encrypt", "--trust-model", "always"];
        if (req.signWith) args.push("--sign", "--local-user", req.signWith);
        if (this.cfg.hideRecipientKeyIds) args.push("--throw-keyids");
        for (const f of req.recipients) args.push("--recipient", f);
        return args;
    }

    async encryptAndSign(req: { plaintext: string; recipients: Fingerprint[]; signWith: Fingerprint | null }): Promise<EncryptResult> {
        const check = await this.checkEncryptParties(req);
        if (!check.ok) return check;

        const r = await this.run(this.encryptArgs(req, true), req.plaintext);
        const res = interpretEncrypt(r, !!req.signWith, true, partiesOf(req));
        if (!res.ok) return res;
        const parsed = parseArmor(r.stdout, "MESSAGE");
        if (!parsed) return fail("gpg-error", "gpg produced unparseable armor");
        return { ok: true, armored: parsed.armored, signed: res.signed };
    }

    /** Who does this signature vouch for, given who Discord says sent it? */
    private async verdictFor(sig: SignatureInfo, req: { authorUserId: Snowflake | null; authorIsSelf?: boolean }): Promise<SigVerdict> {
        if (req.authorIsSelf && (sig.status === "good") && (await this.ownFingerprints()).has(sig.primaryFingerprint)) {
            return { kind: "self", fingerprint: sig.primaryFingerprint };
        }
        const binding = req.authorUserId ? this.cfg.bindings.get(req.authorUserId) : null;
        return computeVerdict(sig, binding);
    }

    async decrypt(req: { armored: string; authorUserId: Snowflake | null; authorIsSelf?: boolean; channelId?: Snowflake | null }): Promise<DecryptResult> {
        const parsed = parseArmor(req.armored, "MESSAGE");
        if (!parsed) return fail("malformed", "not a PGP message");

        const r = await this.run(["--decrypt", "--max-output", String(DECRYPT_MAX_OUTPUT_BYTES)], parsed.armored);
        const res = interpretDecrypt(r);
        if (!res.ok) return res;
        return {
            ok: true, ...res.value,
            verdict: await this.verdictFor(res.value.signature, req),
            channelMismatch: channelMismatch(res.value.signature, req.channelId),
        };
    }

    /**
     * Sign WITHOUT encrypting. Text mode only, short text only (schema), and every signature carries a
     * notation naming the channel so a copied signature is recognisable. The session gate and rate limit
     * live in native/index.ts.
     */
    async sign(req: { text: string; channelId: Snowflake; signWith: Fingerprint }): Promise<SignResult> {
        if (!(await this.ownFingerprints()).has(req.signWith)) return fail("no-own-key", "signing key is not one of your secret keys");
        const exact = await this.resolveExact([req.signWith]);
        if (!exact.ok) return exact;
        const args = ["--armor", "--textmode", "--local-user", req.signWith, "--sig-notation", `${CHANNEL_NOTATION}=${req.channelId}`, "--clear-sign"];

        const r = await this.run(args, req.text);
        const res = interpretSign(r);
        if (!res.ok) return res;
        const parsed = parseArmor(r.stdout, "SIGNED MESSAGE");
        if (!parsed) return fail("gpg-error", "gpg produced unparseable armor");
        return { ok: true, armored: parsed.armored };
    }

    /** Verify a sign-only message. Refuses to act as a decrypt path (encrypted input is an error). */
    async verify(req: VerifyRequest): Promise<VerifyResult> {
        if (req.kind === "detached") {
            const sig = parseArmor(req.signature, "SIGNATURE");
            if (!sig) return fail("malformed", "not a PGP signature");
            // gpg wants the detached signature in a file; the signature is public data, the text goes via stdin.
            const dir = await mkdtemp(join(tmpdir(), "discordpg-sig-"));
            try {
                const sigPath = join(dir, "sig.asc");
                await writeFile(sigPath, sig.armored, { mode: 0o600 });
                const r = await this.run(["--verify", sigPath, "-"], req.text);
                const res = interpretDetachedVerify(r);
                if (!res.ok) return res;
                return this.finishVerify(req, req.text, res.signature);
            } finally {
                await rm(dir, { recursive: true, force: true }).catch(() => { });
            }
        }
        const parsed = parseArmor(req.armored, req.kind === "clearsign" ? "SIGNED MESSAGE" : "MESSAGE");
        if (!parsed) return fail("malformed", req.kind === "clearsign" ? "not a clearsigned message" : "not a PGP message");
        const r = await this.run(["--decrypt", "--max-output", String(DECRYPT_MAX_OUTPUT_BYTES)], parsed.armored);
        const res = interpretVerify(r);
        if (!res.ok) return res;
        return this.finishVerify(req, res.value.plaintext, res.value.signature);
    }

    private async finishVerify(req: VerifyRequest, text: string, signature: SignatureInfo): Promise<VerifyResult> {
        return {
            ok: true,
            plaintext: text,
            signature,
            verdict: await this.verdictFor(signature, req),
            encryptedTo: [],
            mode: "signed",
            channelMismatch: channelMismatch(signature, req.channelId),
        };
    }

    /** Binary OpenPGP output for a `.gpg` attachment. Same trust rules as encryptAndSign. */
    async encryptAttachment(req: { data: Uint8Array; filename: string; recipients: Fingerprint[]; signWith: Fingerprint | null }): Promise<AttachmentEncryptResult> {
        const check = await this.checkEncryptParties(req);
        if (!check.ok) return check;
        if (req.data.byteLength > ATTACHMENT_MAX_BYTES) return fail("oversize", "attachment too large");

        const r = await this.run(this.encryptArgs(req, false), toBuffer(req.data), this.cfg.timeoutMs, {
            binaryStdout: true,
            stdoutCap: ATTACHMENT_MAX_BYTES + 1024 * 1024,
        });
        const res = interpretEncrypt(r, !!req.signWith, false, partiesOf(req));
        if (!res.ok) return res;
        return { ok: true, data: new Uint8Array(r.stdoutBytes!), signed: res.signed };
    }

    /**
     * Decrypts a `.gpg` / `.pgp` / `.asc` attachment. "preview" hands image bytes back to the renderer;
     * "save" writes the file through cfg.saver (an OS dialog in production) and returns only the path.
     */
    async decryptAttachment(req: { data: Uint8Array; filename: string; authorUserId: Snowflake | null; authorIsSelf?: boolean; action: AttachmentAction }): Promise<AttachmentDecryptResult> {
        if (req.data.byteLength > ATTACHMENT_MAX_BYTES) return fail("oversize", "attachment too large");
        let input = toBuffer(req.data);
        if (looksArmored(req.data)) {
            // Armored files still go through the strict grammar before gpg sees them.
            const parsed = parseArmor(input.toString("latin1"), "MESSAGE", { maxBytes: ATTACHMENT_MAX_BYTES });
            if (!parsed) return fail("malformed", "not a PGP message");
            input = Buffer.from(parsed.armored, "latin1");
        }

        const r = await this.run(["--decrypt", "--max-output", String(ATTACHMENT_DECRYPT_MAX_OUTPUT_BYTES)], input, this.cfg.timeoutMs, {
            binaryStdout: true,
            stdoutCap: ATTACHMENT_DECRYPT_MAX_OUTPUT_BYTES + 64 * 1024,
        });
        const res = interpretDecrypt(r);
        if (!res.ok) return res;
        const bytes = r.stdoutBytes ?? Buffer.alloc(0);
        const verdict = await this.verdictFor(res.value.signature, req);
        const base = { signature: res.value.signature, verdict, size: bytes.length };

        if (req.action === "preview") {
            if (bytes.length > PREVIEW_MAX_BYTES) return fail("oversize", "too large to preview; save it instead");
            const mime = sniffImage(bytes);
            if (!mime) return fail("malformed", "not an image; save it instead");
            return { ok: true, ...base, action: "preview", data: new Uint8Array(bytes), mime };
        }
        if (!this.cfg.saver) return fail("gpg-error", "saving is not available");
        const savedTo = await this.cfg.saver({ suggestedName: req.filename, bytes, warning: verdictWarning(verdict) });
        if (!savedTo) return fail("cancelled");
        return { ok: true, ...base, action: "save", savedTo };
    }

    async lock(): Promise<void> {
        this.secretKeys = null;
        await reloadAgent(this.cfg.gpgPath, this.cfg.homedir);
    }

    async version(): Promise<{ gpg: string | null; libgcrypt: string | null }> {
        const r = await this.run(["--version"], undefined, 10_000);
        const gpg = /^gpg \(GnuPG\) (\S+)/m.exec(r.stdout)?.[1] ?? null;
        const libgcrypt = /^libgcrypt (\S+)/m.exec(r.stdout)?.[1] ?? null;
        return { gpg, libgcrypt };
    }

    async cardStatus(): Promise<{ present: boolean; serial: string | null }> {
        const r = await this.run(["--card-status", "--with-colons"], undefined, 15_000);
        if (r.exitCode !== 0) return { present: false, serial: null };
        const serial = /^serial:([0-9A-Fa-f]+):/m.exec(r.stdout)?.[1] ?? null;
        return { present: !!serial, serial };
    }
}

export function computeVerdict(sig: SignatureInfo, binding: Binding | null): SigVerdict {
    switch (sig.status) {
        case "none": return { kind: "unsigned" };
        case "bad": return { kind: "bad" };
        case "unknown-key": return { kind: "unknown-signer", keyId: sig.keyId };
        case "good-revoked-key":
            // A revoked key can no longer vouch for anyone, whoever it is bound to.
            return { kind: "mismatch", fingerprint: sig.primaryFingerprint, expected: binding?.fingerprint ?? null };
        case "good":
        case "good-expired-key": {
            if (!binding || binding.fingerprint !== sig.primaryFingerprint) {
                return { kind: "mismatch", fingerprint: sig.primaryFingerprint, expected: binding?.fingerprint ?? null };
            }
            if (sig.status === "good" && binding.verified) return { kind: "verified", fingerprint: sig.primaryFingerprint };
            return { kind: "unverified-contact", fingerprint: sig.primaryFingerprint };
        }
    }
}
