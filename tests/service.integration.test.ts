import { join } from "path";
import { afterAll, beforeAll, describe, expect, test } from "vitest";

import { BindingStore } from "../native/bindings";
import { reloadAgent, runGpgRaw } from "../native/gpg";
import { computeVerdict, GpgService } from "../native/service";
import { extractArmor, wrapForDiscord } from "../core/wire";
import { LOOPBACK, makeHome, TestHome } from "./helpers/gnupghome";

const ALICE_ID = "100000000000000001";
const BOB_ID = "100000000000000002";
const MALLORY_ID = "100000000000000003";

let home: TestHome;
let alice: string, bob: string, mallory: string;
let bindings: BindingStore;
let svc: GpgService;

beforeAll(async () => {
    home = await makeHome();
    // Sequential on purpose: concurrent key generation in one GNUPGHOME corrupts the keyring.
    alice = await home.genKey("Alice <alice@example.invalid>");
    bob = await home.genKey("Bob <bob@example.invalid>");
    mallory = await home.genKey("Mallory <mallory@example.invalid>");
    bindings = new BindingStore(join(home.dir, "bindings.json"));
    await bindings.load();
    svc = new GpgService({ gpgPath: home.gpg, homedir: home.dir, bindings, timeoutMs: 30_000, hideRecipientKeyIds: false, extraArgs: LOOPBACK });
}, 60_000);

afterAll(async () => { await home?.cleanup(); });

describe("GpgService against a real gpg", () => {
    test("lists secret keys with subkeys", async () => {
        const r = await svc.listSecretKeys(true);
        expect(r.ok).toBe(true);
        if (!r.ok) return;
        expect(r.keys.map(k => k.fingerprint).sort()).toEqual([alice, bob, mallory].sort());
        expect(r.keys[0].subkeys.map(s => s.capabilities).sort()).toEqual(["e", "s"]);
    });

    test("own keys are always allowed recipients; a public-only unbound key is refused until bound", async () => {
        const own = await svc.encryptAndSign({ plaintext: "hi", recipients: [bob, alice], signWith: alice });
        expect(own.ok).toBe(true);

        const other = await makeHome();
        try {
            const stranger = await other.genKey("Stranger <stranger@example.invalid>");
            const { stdout: pub } = await other.run(["--armor", "--export", stranger]);
            const imp = await svc.importPublicKey(pub);
            expect(imp.ok && imp.fingerprints).toEqual([stranger]);

            const denied = await svc.encryptAndSign({ plaintext: "hi", recipients: [stranger], signWith: null });
            expect(denied).toMatchObject({ ok: false, error: "invalid-recipient" });
            expect(await svc.exportPublicKey(stranger)).toMatchObject({ ok: false, error: "invalid-recipient" });

            await bindings.bind(MALLORY_ID, stranger);
            const allowed = await svc.encryptAndSign({ plaintext: "hi", recipients: [stranger, alice], signWith: alice });
            expect(allowed.ok).toBe(true);
            expect((await svc.exportPublicKey(stranger)).ok).toBe(true);
            await bindings.unbind(MALLORY_ID);
        } finally {
            await other.cleanup();
        }
    });

    test("export is limited to own/bound keys; import of a public key works and refuses secrets", async () => {
        const exp = await svc.exportPublicKey(alice);
        expect(exp.ok).toBe(true);
        if (!exp.ok) return;
        expect(exp.armored.startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----")).toBe(true);

        const imp = await svc.importPublicKey(exp.armored);
        expect(imp.ok).toBe(true);
        if (imp.ok) {
            expect(imp.fingerprints).toEqual([alice]);
            expect(imp.keys[0].uids[0].uid).toContain("Alice");
        }

        const { stdout: secret } = await home.run([...LOOPBACK, "--armor", "--export-secret-keys", alice]);
        expect(secret).toContain("PRIVATE KEY BLOCK");
        expect(await svc.importPublicKey(secret)).toMatchObject({ ok: false, error: "secret-key-block" });
        expect(await svc.importPublicKey("garbage")).toMatchObject({ ok: false, error: "malformed" });
    });

    test("round trip: encrypt+sign to bound contact + self, decrypt with verdicts", async () => {
        await bindings.bind(BOB_ID, bob);
        const enc = await svc.encryptAndSign({ plaintext: "hello **bob** <@123>", recipients: [bob, alice], signWith: alice });
        expect(enc.ok).toBe(true);
        if (!enc.ok) return;
        expect(enc.signed).toBe(true);
        expect(enc.armored.length).toBeLessThan(900);

        // What Discord would carry:
        const wire = wrapForDiscord(enc.armored, true);
        const block = extractArmor(wire, "MESSAGE")!;
        expect(block.armored).toBe(enc.armored);

        // Receiving side knows the author is "alice" but has no binding for her yet -> mismatch
        const dec1 = await svc.decrypt({ armored: block.armored, authorUserId: ALICE_ID });
        expect(dec1.ok).toBe(true);
        if (!dec1.ok) return;
        expect(dec1.plaintext).toBe("hello **bob** <@123>");
        expect(dec1.signature.status).toBe("good");
        expect(dec1.verdict).toEqual({ kind: "mismatch", fingerprint: alice, expected: null });
        expect(dec1.encryptedTo).toHaveLength(2);

        await bindings.bind(ALICE_ID, alice);
        const dec2 = await svc.decrypt({ armored: block.armored, authorUserId: ALICE_ID });
        expect(dec2.ok && dec2.verdict).toEqual({ kind: "unverified-contact", fingerprint: alice });

        await bindings.setVerified(ALICE_ID, alice, true);
        const dec3 = await svc.decrypt({ armored: block.armored, authorUserId: ALICE_ID });
        expect(dec3.ok && dec3.verdict).toEqual({ kind: "verified", fingerprint: alice });

        // Claimed author is bob, but alice signed -> mismatch with expected fingerprint
        const dec4 = await svc.decrypt({ armored: block.armored, authorUserId: BOB_ID });
        expect(dec4.ok && dec4.verdict).toEqual({ kind: "mismatch", fingerprint: alice, expected: bob });

        // Unknown author -> mismatch with null expectation (never "verified")
        const dec5 = await svc.decrypt({ armored: block.armored, authorUserId: null });
        expect(dec5.ok && dec5.verdict.kind).toBe("mismatch");
    });

    test("unsigned message", async () => {
        const enc = await svc.encryptAndSign({ plaintext: "nosig", recipients: [bob], signWith: null });
        expect(enc.ok && enc.signed).toBe(false);
        if (!enc.ok) return;
        const dec = await svc.decrypt({ armored: enc.armored, authorUserId: BOB_ID });
        expect(dec.ok && dec.verdict).toEqual({ kind: "unsigned" });
    });

    test("interop: gpg CLI decrypts our output, we decrypt gpg CLI output", async () => {
        const enc = await svc.encryptAndSign({ plaintext: "interop", recipients: [bob], signWith: alice });
        if (!enc.ok) throw new Error(enc.error);
        const { stdout } = await home.run([...LOOPBACK, "--decrypt"], enc.armored);
        expect(stdout).toBe("interop");

        const { stdout: cli } = await home.run([...LOOPBACK, "--armor", "--encrypt", "--sign", "--local-user", mallory, "--trust-model", "always", "-r", alice], "from mallory");
        const dec = await svc.decrypt({ armored: cli, authorUserId: ALICE_ID });
        expect(dec.ok && dec.plaintext).toBe("from mallory");
        expect(dec.ok && dec.verdict).toEqual({ kind: "mismatch", fingerprint: mallory, expected: alice });
    });

    test("not-for-you", async () => {
        const other = await makeHome();
        try {
            const stranger = await other.genKey("Stranger <s@example.invalid>");
            const { stdout } = await other.run([...LOOPBACK, "--armor", "--encrypt", "--trust-model", "always", "-r", stranger], "secret");
            const dec = await svc.decrypt({ armored: stdout, authorUserId: null });
            expect(dec).toMatchObject({ ok: false, error: "not-for-you" });
        } finally {
            await other.cleanup();
        }
    });

    test("tampered ciphertext fails closed", async () => {
        const enc = await svc.encryptAndSign({ plaintext: "integrity", recipients: [bob], signWith: alice });
        if (!enc.ok) throw new Error(enc.error);
        const lines = enc.armored.split("\n");
        // flip a character deep inside the encrypted body (not the first packet, not the CRC)
        const bodyIdx = lines.findIndex((l, i) => i > 2 && l.length === 64 && !l.startsWith("="));
        const target = lines[bodyIdx + 1] ?? lines[bodyIdx];
        const ti = lines.indexOf(target);
        lines[ti] = target.slice(0, 20) + (target[20] === "A" ? "B" : "A") + target.slice(21);
        const tampered = lines.join("\n");
        const dec = await svc.decrypt({ armored: tampered, authorUserId: BOB_ID });
        expect(dec.ok).toBe(false);
    });

    test("decompression bomb is capped by --max-output", async () => {
        const big = "A".repeat(3 * 1024 * 1024);
        const { stdout } = await home.run([...LOOPBACK, "--armor", "--encrypt", "--compress-algo", "zlib", "--trust-model", "always", "-r", bob], big);
        expect(stdout.length).toBeLessThan(64 * 1024);
        const dec = await svc.decrypt({ armored: stdout, authorUserId: null });
        expect(dec.ok).toBe(false);
    });

    test("wrong passphrase maps to pin-cancelled (verifies BAD_PASSPHRASE code)", async () => {
        const locked = await home.genKey("Locked <locked@example.invalid>", "correct horse");
        const { stdout } = await home.run([...LOOPBACK, "--armor", "--encrypt", "--trust-model", "always", "-r", locked], "x");
        const run = await runGpgRaw({ gpgPath: home.gpg, homedir: home.dir, args: ["--pinentry-mode", "loopback", "--passphrase", "wrong", "--decrypt"], stdin: stdout, timeoutMs: 20_000 });
        expect(run.stderr).toMatch(/BAD_PASSPHRASE|ERROR pkdecrypt_failed/);
        const { interpretDecrypt } = await import("../native/status");
        expect(interpretDecrypt(run)).toMatchObject({ ok: false, error: "pin-cancelled" });
    });

    // runGpgRaw always prepends the hardening flags, so stand-ins must be scripts that ignore their arguments.
    async function fakeGpg(name: string, body: string): Promise<string> {
        const { writeFile, chmod } = await import("fs/promises");
        const p = join(home.dir, name);
        await writeFile(p, "#!/bin/sh\n" + body + "\n");
        await chmod(p, 0o755);
        return p;
    }

    test("timeout is enforced and kills the child", async () => {
        const started = Date.now();
        const run = await runGpgRaw({ gpgPath: await fakeGpg("hang.sh", "sleep 30"), args: [], timeoutMs: 300 });
        expect(run.timedOut).toBe(true);
        expect(Date.now() - started).toBeLessThan(5000);
        const { interpretDecrypt } = await import("../native/status");
        expect(interpretDecrypt(run)).toMatchObject({ ok: false, error: "timeout" });
    });

    test("output cap aborts runaway stdout", async () => {
        const run = await runGpgRaw({ gpgPath: await fakeGpg("spew.sh", "exec yes"), args: [], timeoutMs: 10_000, stdoutCap: 4096 });
        expect(run.signal).toBe("OVERFLOW");
        expect(run.exitCode).toBeNull();
    });

    test("self verdict for messages we signed ourselves", async () => {
        const enc = await svc.encryptAndSign({ plaintext: "mine", recipients: [bob, alice], signWith: alice });
        if (!enc.ok) throw new Error(enc.error);
        const dec = await svc.decrypt({ armored: enc.armored, authorUserId: null, authorIsSelf: true });
        expect(dec.ok && dec.verdict).toEqual({ kind: "self", fingerprint: alice });
        // claiming "self" for a message someone else signed must not work (mallory is also "own" in this shared test keyring, so use an outsider)
        const other = await makeHome();
        try {
            const stranger = await other.genKey("Stranger2 <stranger2@example.invalid>");
            const { stdout: strangerPub } = await other.run(["--armor", "--export", stranger]);
            await svc.importPublicKey(strangerPub);
            const { stdout: alicePub } = await home.run(["--armor", "--export", alice]);
            await other.run(["--import"], alicePub);
            const { stdout: cli } = await other.run([...LOOPBACK, "--armor", "--encrypt", "--sign", "--local-user", stranger, "--trust-model", "always", "-r", alice], "fake");
            const dec2 = await svc.decrypt({ armored: cli, authorUserId: null, authorIsSelf: true });
            expect(dec2.ok && dec2.signature.status).toBe("good");
            expect(dec2.ok && dec2.verdict).toEqual({ kind: "mismatch", fingerprint: stranger, expected: null });
        } finally {
            await other.cleanup();
        }
    });

    test("lock reloads the agent without error", async () => {
        await expect(reloadAgent(home.gpg, home.dir)).resolves.toBeUndefined();
        await expect(svc.lock()).resolves.toBeUndefined();
    });

    test("computeVerdict edge cases", () => {
        expect(computeVerdict({ status: "good-revoked-key", fingerprint: alice, primaryFingerprint: alice, timestamp: 0 }, { userId: ALICE_ID, fingerprint: alice, verified: true, addedAt: 0, changedAt: null, previousFingerprints: [] }).kind).toBe("mismatch");
        expect(computeVerdict({ status: "good-expired-key", fingerprint: alice, primaryFingerprint: alice, timestamp: 0 }, { userId: ALICE_ID, fingerprint: alice, verified: true, addedAt: 0, changedAt: null, previousFingerprints: [] }).kind).toBe("unverified-contact");
    });
});
