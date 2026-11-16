import { existsSync, readFileSync } from "fs";
import { join } from "path";
import { describe, expect, test } from "vitest";

import { BindingStore } from "../native/bindings";
import { GpgService } from "../native/service";
import { LOOPBACK, makeHome, TestHome } from "./helpers/gnupghome";

const fx = (n: string) => readFileSync(new URL(`./fixtures/${n}`, import.meta.url), "utf8");

async function serviceFor(home: TestHome) {
    const bindings = new BindingStore(join(home.dir, "bindings.json"));
    await bindings.load();
    const svc = new GpgService({ gpgPath: home.gpg, homedir: home.dir, bindings, timeoutMs: 30_000, hideRecipientKeyIds: false, extraArgs: LOOPBACK });
    return { svc, bindings };
}

const records = async (home: TestHome, args: string[]) => (await home.run(["--with-colons", ...args])).stdout.split("\n").map(l => l.split(":")[0]);

describe("import: the armor label is not trusted", () => {
    test("a secret key relabelled as a PUBLIC KEY BLOCK is refused before anything reaches the keyring", async () => {
        const attacker = await makeHome();
        const victim = await makeHome();
        try {
            const evil = await attacker.genKey("Mallory <mallory@example.invalid>");
            const { stdout: secret } = await attacker.run([...LOOPBACK, "--armor", "--export-secret-keys", evil]);
            expect(secret).toContain("-----BEGIN PGP PRIVATE KEY BLOCK-----");
            const disguised = secret.replace(/PRIVATE KEY BLOCK/g, "PUBLIC KEY BLOCK");

            const { svc } = await serviceFor(victim);
            expect(await svc.importPublicKey(disguised)).toMatchObject({ ok: false, error: "secret-key-block" });

            // The point of the fix: refusing is not enough if gpg already imported it.
            expect(await records(victim, ["--list-secret-keys"])).not.toContain("sec");
            expect(await records(victim, ["--list-keys"])).not.toContain("pub");
            const own = await svc.listSecretKeys(true);
            expect(own.ok && own.keys).toEqual([]);

            // The genuine public key of the same key pair still imports.
            const { stdout: pub } = await attacker.run(["--armor", "--export", evil]);
            const imp = await svc.importPublicKey(pub);
            expect(imp.ok && imp.fingerprints).toEqual([evil]);
            expect(await records(victim, ["--list-secret-keys"])).not.toContain("sec");
        } finally {
            await attacker.cleanup();
            await victim.cleanup();
        }
    }, 60_000);
});

/**
 * Fixtures (throwaway keys, public parts only):
 *  - confusion-victim.pub.asc:   "Bob", primary VICTIM, encryption subkey VICTIM_ENC.
 *  - confusion-impostor.pub.asc: "Mallory", primary IMPOSTOR, encryption subkey IMPOSTOR_ENC, plus a second
 *    subkey that IS Bob's primary key (same key material and creation time, hence the same fingerprint).
 *    Building that needs only Bob's public key: a non-signing subkey requires no proof of possession.
 * With both in a keyring, `--recipient VICTIM` can resolve to Mallory's keyblock and encrypt to IMPOSTOR_ENC.
 */
const VICTIM = "AFF9F2E94CFE9A769DAC8D44385271A54B32CDA6";
const VICTIM_ENC = "6B2914116636E32D";
const IMPOSTOR = "0DC28D96CD804C19DC496C39248E4C5D8BCD9A76";
const IMPOSTOR_ENC = "3808DF142C09DD91";
const BOB_ID = "100000000000000002";

describe.each([
    { backend: "pubring.kbx", keyboxd: false },
    { backend: "keyboxd", keyboxd: true },
])("a fingerprint must select the key it names ($backend)", ({ keyboxd }) => {
    describe.each([
        { order: "impostor imported first", files: ["confusion-impostor.pub.asc", "confusion-victim.pub.asc"] },
        { order: "impostor imported last", files: ["confusion-victim.pub.asc", "confusion-impostor.pub.asc"] },
    ])("$order", ({ files }) => {
        test("never encrypts to the impostor; refuses when the fingerprint is ambiguous", async () => {
            const home = await makeHome({ keyboxd });
            try {
                const { svc, bindings } = await serviceFor(home);
                for (const f of files) expect((await svc.importPublicKey(fx(f))).ok).toBe(true);
                const usingKeyboxd = existsSync(join(home.dir, "public-keys.d", "pubring.db"));
                if (keyboxd && !usingKeyboxd) return; // gpg too old for keyboxd: the kbx variant already covered it

                // What the raw gpg lookup does here, i.e. what the plugin did before the fix.
                const raw = await home.run(["--armor", "--encrypt", "--trust-model", "always", "--recipient", VICTIM], "x");
                const rawTo = (await home.run(["--list-packets"], raw.stdout)).stdout;
                const gpgPicksImpostor = rawTo.includes(IMPOSTOR_ENC);

                // The user binds Bob's fingerprint (the native dialog showed exactly this fingerprint).
                await bindings.bind(BOB_ID, VICTIM);
                const resolved = await svc.resolveExact([VICTIM]);
                const enc = await svc.encryptAndSign({ plaintext: "for bob only", recipients: [VICTIM], signWith: null });
                const file = await svc.encryptAttachment({ data: new Uint8Array([1, 2, 3]), filename: "a.bin", recipients: [VICTIM], signWith: null });

                if (enc.ok) {
                    // Only acceptable when gpg really selected Bob's own keyblock.
                    const to = (await home.run(["--list-packets"], enc.armored)).stdout;
                    expect(to).toContain(VICTIM_ENC);
                    expect(to).not.toContain(IMPOSTOR_ENC);
                    expect(gpgPicksImpostor).toBe(false);
                    expect(resolved.ok && resolved.keys.map(k => k.fingerprint)).toEqual([VICTIM]);
                    expect(file.ok).toBe(true);
                } else {
                    expect(enc.error).toBe("ambiguous-key");
                    expect(resolved).toMatchObject({ ok: false, error: "ambiguous-key" });
                    expect(file).toMatchObject({ ok: false, error: "ambiguous-key" });
                    expect(await svc.exportPublicKey(VICTIM)).toMatchObject({ ok: false, error: "ambiguous-key" });
                }
                // Whenever plain gpg would have picked the impostor, we must have refused.
                if (gpgPicksImpostor) expect(enc.ok).toBe(false);
                // The classic keyring lists both keyblocks, so there the ambiguity is always visible.
                if (!usingKeyboxd) expect(enc.ok).toBe(false);

                // The impostor's own fingerprint is still an ordinary, unambiguous key.
                const self = await svc.resolveExact([IMPOSTOR]);
                expect(self.ok && self.keys.map(k => k.fingerprint)).toEqual([IMPOSTOR]);
            } finally {
                await home.cleanup();
            }
        }, 60_000);
    });
});

describe("resolveExact", () => {
    test("unknown fingerprints and subkey fingerprints are not accepted as keys", async () => {
        const home = await makeHome();
        try {
            const { svc } = await serviceFor(home);
            expect((await svc.importPublicKey(fx("confusion-victim.pub.asc"))).ok).toBe(true);
            expect(await svc.resolveExact([])).toEqual({ ok: true, keys: [] });
            expect(await svc.resolveExact([IMPOSTOR])).toMatchObject({ ok: false, error: "invalid-recipient" });
            const { stdout } = await home.run(["--with-colons", "--with-fingerprint", "--with-fingerprint", "--list-keys", VICTIM]);
            const subFpr = stdout.split("\n").filter(l => l.startsWith("fpr:")).map(l => l.split(":")[9])[1];
            expect(subFpr).toMatch(/^[0-9A-F]{40}$/);
            // gpg happily lists Bob's key for his subkey fingerprint; a binding must name the primary key.
            expect(await svc.resolveExact([subFpr])).toMatchObject({ ok: false, error: "ambiguous-key" });
            const ok = await svc.resolveExact([VICTIM, VICTIM]);
            expect(ok.ok && ok.keys.map(k => k.fingerprint)).toEqual([VICTIM]);
        } finally {
            await home.cleanup();
        }
    }, 60_000);
});
