import { randomBytes } from "crypto";
import { mkdtemp, readFile, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { afterAll, beforeAll, describe, expect, test } from "vitest";

import { BindingStore } from "../native/bindings";
import { GpgService } from "../native/service";
import { LOOPBACK, makeHome, TestHome } from "./helpers/gnupghome";

const BOB_ID = "100000000000000002";

let home: TestHome;
let alice: string, bob: string;
let svc: GpgService;
let saveDir: string;
let lastWarning: string | null | undefined;
let saverCancels = false;

beforeAll(async () => {
    home = await makeHome();
    alice = await home.genKey("Alice <alice@example.invalid>");
    bob = await home.genKey("Bob <bob@example.invalid>");
    const bindings = new BindingStore(join(home.dir, "bindings.json"));
    await bindings.load();
    await bindings.bind(BOB_ID, bob);
    saveDir = await mkdtemp(join(tmpdir(), "discordpg-save-"));
    svc = new GpgService({
        gpgPath: home.gpg, homedir: home.dir, bindings, timeoutMs: 30_000, hideRecipientKeyIds: false, extraArgs: LOOPBACK,
        saver: async ({ suggestedName, bytes, warning }) => {
            lastWarning = warning;
            if (saverCancels) return null;
            const p = join(saveDir, suggestedName);
            await (await import("fs/promises")).writeFile(p, bytes);
            return p;
        },
    });
}, 60_000);

afterAll(async () => { await home?.cleanup(); await rm(saveDir, { recursive: true, force: true }); });

const PNG = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), randomBytes(4096)]);

describe("attachments against a real gpg", () => {
    test("binary round trip is byte-exact, signed, and previews as an image", async () => {
        const enc = await svc.encryptAttachment({ data: new Uint8Array(PNG), filename: "pic.png", recipients: [bob, alice], signWith: alice });
        expect(enc.ok).toBe(true);
        if (!enc.ok) return;
        expect(enc.signed).toBe(true);
        expect(enc.data[0]).not.toBe(0x2d); // binary, not armor ("-")

        const dec = await svc.decryptAttachment({ data: enc.data, filename: "pic.png.gpg", authorUserId: null, authorIsSelf: true, action: "preview" });
        expect(dec.ok).toBe(true);
        if (!dec.ok || dec.action !== "preview") return;
        expect(dec.mime).toBe("image/png");
        expect(Buffer.from(dec.data).equals(PNG)).toBe(true);
        expect(dec.verdict.kind).toBe("self");
        expect(dec.size).toBe(PNG.length);
    });

    test("a large random file survives (1 MiB)", async () => {
        const big = randomBytes(1024 * 1024);
        const enc = await svc.encryptAttachment({ data: new Uint8Array(big), filename: "blob.bin", recipients: [alice], signWith: null });
        expect(enc.ok).toBe(true);
        if (!enc.ok) return;
        lastWarning = undefined;
        const dec = await svc.decryptAttachment({ data: enc.data, filename: "blob.bin", authorUserId: BOB_ID, authorIsSelf: false, action: "save" });
        expect(dec.ok).toBe(true);
        if (!dec.ok || dec.action !== "save") return;
        expect((await readFile(dec.savedTo)).equals(big)).toBe(true);
        expect(dec.verdict.kind).toBe("unsigned");
        expect(lastWarning).toMatch(/not signed/);
    });

    test("preview refuses non-images; save honours cancellation", async () => {
        const enc = await svc.encryptAttachment({ data: new Uint8Array(Buffer.from("%PDF-1.7 hello")), filename: "doc.pdf", recipients: [alice], signWith: alice });
        expect(enc.ok).toBe(true);
        if (!enc.ok) return;
        const prev = await svc.decryptAttachment({ data: enc.data, filename: "doc.pdf.gpg", authorUserId: null, authorIsSelf: true, action: "preview" });
        expect(prev).toMatchObject({ ok: false, error: "malformed" });
        saverCancels = true;
        try {
            const saved = await svc.decryptAttachment({ data: enc.data, filename: "doc.pdf.gpg", authorUserId: null, authorIsSelf: true, action: "save" });
            expect(saved).toMatchObject({ ok: false, error: "cancelled" });
        } finally { saverCancels = false; }
    });

    test("armored .asc attachments decrypt too; tampering is detected; unbound recipients are refused", async () => {
        const { stdout: asc } = await home.run([...LOOPBACK, "--armor", "--encrypt", "--trust-model", "always", "-r", alice], "secret file body");
        const dec = await svc.decryptAttachment({ data: new Uint8Array(Buffer.from(asc)), filename: "x.txt.asc", authorUserId: BOB_ID, authorIsSelf: false, action: "save" });
        expect(dec.ok).toBe(true);
        if (dec.ok && dec.action === "save") expect((await readFile(dec.savedTo)).toString()).toBe("secret file body");

        const enc = await svc.encryptAttachment({ data: new Uint8Array(PNG), filename: "pic.png", recipients: [alice], signWith: alice });
        if (!enc.ok) throw new Error("encrypt failed");
        const bad = new Uint8Array(enc.data);
        bad[bad.length - 20] ^= 0xff;
        const t = await svc.decryptAttachment({ data: bad, filename: "pic.png.gpg", authorUserId: null, authorIsSelf: true, action: "preview" });
        expect(t.ok).toBe(false);

        const other = await makeHome();
        try {
            const stranger = await other.genKey("Stranger <s@example.invalid>");
            const { stdout: pub } = await other.run(["--armor", "--export", stranger]);
            await svc.importPublicKey(pub);
            const denied = await svc.encryptAttachment({ data: new Uint8Array(PNG), filename: "pic.png", recipients: [stranger], signWith: null });
            expect(denied).toMatchObject({ ok: false, error: "invalid-recipient" });
        } finally { await other.cleanup(); }
    });
});
