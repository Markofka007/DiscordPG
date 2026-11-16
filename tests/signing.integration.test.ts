import { join } from "path";
import { afterAll, beforeAll, describe, expect, test } from "vitest";

import { BindingStore } from "../native/bindings";
import { GpgService } from "../native/service";
import { parseArmor, wrapForDiscord } from "../core/wire";
import { LOOPBACK, makeHome, TestHome } from "./helpers/gnupghome";

const ALICE_ID = "100000000000000001";
const CHAN = "200000000000000001";
const OTHER_CHAN = "200000000000000002";

let home: TestHome;
let alice: string, bob: string;
let bindings: BindingStore;
let svc: GpgService;

beforeAll(async () => {
    home = await makeHome();
    alice = await home.genKey("Alice <alice@example.invalid>");
    bob = await home.genKey("Bob <bob@example.invalid>");
    bindings = new BindingStore(join(home.dir, "bindings.json"));
    await bindings.load();
    await bindings.bind(ALICE_ID, alice);
    svc = new GpgService({ gpgPath: home.gpg, homedir: home.dir, bindings, timeoutMs: 30_000, hideRecipientKeyIds: false, extraArgs: LOOPBACK });
}, 60_000);

afterAll(async () => { await home?.cleanup(); });

const TEXT = "héllo **bob**\n- item one\n- item two";

/** Sign with plain gpg the way another client (or an older DiscordPG) would, for the incoming-verify paths. */
const gpgSign = async (flag: "--sign" | "--detach-sign", key: string, text: string) =>
    (await home.run(["--armor", "--textmode", "--local-user", key, "--sig-notation", `channel@discordpg.invalid=${CHAN}`, flag], text)).stdout;

describe("sign-only against a real gpg", () => {
    test("clearsign round trip, verdict from the author binding, channel notation honoured", async () => {
        const s = await svc.sign({ text: TEXT, channelId: CHAN, signWith: alice });
        expect(s.ok).toBe(true);
        if (!s.ok) return;
        expect(s.armored.startsWith("-----BEGIN PGP SIGNED MESSAGE-----")).toBe(true);
        expect(s.armored).toContain("- - item one"); // dash escaping

        const v = await svc.verify({ kind: "clearsign", armored: s.armored, channelId: CHAN, authorUserId: ALICE_ID, authorIsSelf: false });
        expect(v.ok).toBe(true);
        if (!v.ok) return;
        expect(v.plaintext.trimEnd()).toBe(TEXT);
        expect(v.mode).toBe("signed");
        expect(v.verdict).toMatchObject({ kind: "unverified-contact", fingerprint: alice });
        expect(v.channelMismatch).toBe(false);

        const replayed = await svc.verify({ kind: "clearsign", armored: s.armored, channelId: OTHER_CHAN, authorUserId: ALICE_ID, authorIsSelf: false });
        expect(replayed.ok && replayed.channelMismatch).toBe(true);

        // Interop: plain gpg verifies the fenced message a non-plugin user would see.
        const wire = wrapForDiscord(s.armored, true);
        const inner = parseArmor(wire.slice(4, -3), "SIGNED MESSAGE");
        expect(inner).not.toBeNull();
        const { stderr } = await home.run(["--status-fd", "2", "--decrypt"], inner!.armored);
        expect(stderr).toContain("[GNUPG:] GOODSIG");
    });

    test("incoming encoded (gpg --sign) message: verify opens it and decrypt reports it as signed-only", async () => {
        const armored = await gpgSign("--sign", alice, TEXT);
        expect(armored.startsWith("-----BEGIN PGP MESSAGE-----")).toBe(true);
        const v = await svc.verify({ kind: "encoded", armored, channelId: CHAN, authorUserId: null, authorIsSelf: true });
        expect(v.ok && v.verdict.kind).toBe("self");
        const d = await svc.decrypt({ armored, authorUserId: ALICE_ID, authorIsSelf: false, channelId: OTHER_CHAN });
        expect(d.ok).toBe(true);
        if (d.ok) {
            expect(d.mode).toBe("signed");
            expect(d.channelMismatch).toBe(true);
            expect(d.plaintext.trimEnd()).toBe(TEXT);
        }
    });

    test("incoming detached signature verifies against the exact text, fails against altered text", async () => {
        const signature = await gpgSign("--detach-sign", alice, TEXT);
        expect(signature.startsWith("-----BEGIN PGP SIGNATURE-----")).toBe(true);
        const v = await svc.verify({ kind: "detached", text: TEXT, signature, channelId: CHAN, authorUserId: ALICE_ID, authorIsSelf: false });
        expect(v.ok && v.verdict.kind).toBe("unverified-contact");
        const bad = await svc.verify({ kind: "detached", text: TEXT + "!", signature, channelId: CHAN, authorUserId: ALICE_ID, authorIsSelf: false });
        expect(bad).toMatchObject({ ok: false, error: "tampered" });
    });

    test("verify is not a decrypt path; signing needs one of our keys; signer mismatch is reported", async () => {
        const enc = await svc.encryptAndSign({ plaintext: "secret", recipients: [alice], signWith: alice });
        if (!enc.ok) throw new Error("encrypt failed");
        expect(await svc.verify({ kind: "encoded", armored: enc.armored, channelId: CHAN, authorUserId: null })).toMatchObject({ ok: false, error: "malformed" });

        const other = await makeHome();
        try {
            const stranger = await other.genKey("Stranger <s@example.invalid>");
            const { stdout: pub } = await other.run(["--armor", "--export", stranger]);
            await svc.importPublicKey(pub);
            expect(await svc.sign({ text: "x", channelId: CHAN, signWith: stranger })).toMatchObject({ ok: false, error: "no-own-key" });
        } finally { await other.cleanup(); }

        const byBob = await svc.sign({ text: TEXT, channelId: CHAN, signWith: bob });
        if (!byBob.ok) throw new Error("sign failed");
        const v = await svc.verify({ kind: "clearsign", armored: byBob.armored, channelId: CHAN, authorUserId: ALICE_ID, authorIsSelf: false });
        expect(v.ok && v.verdict.kind).toBe("mismatch");
    });
});
