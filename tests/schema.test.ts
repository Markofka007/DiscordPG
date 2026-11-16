import { describe, expect, it, test } from "vitest";

import * as S from "../native/schema";

const FPR = "2199C6B42AEA12C46F78B51EC7C73743035A3ECE";

describe("schema", () => {
    test("fingerprint", () => {
        expect(S.fingerprint(FPR)).toBe(FPR);
        expect(() => S.fingerprint(FPR.toLowerCase())).toThrow(S.ValidationError);
        expect(() => S.fingerprint(FPR.slice(0, 16))).toThrow();
        expect(() => S.fingerprint(123)).toThrow();
        expect(() => S.fingerprint(null)).toThrow();
    });
    test("snowflake", () => {
        expect(S.snowflake("343383572805058560")).toBe("343383572805058560");
        expect(() => S.snowflake("abc")).toThrow();
        expect(() => S.snowflake("1")).toThrow();
        expect(() => S.snowflake(343383572805058560n)).toThrow();
    });
    test("armorText rejects non-ascii, NUL and oversize", () => {
        expect(S.armorText("abc\n")).toBe("abc\n");
        expect(() => S.armorText("é")).toThrow();
        expect(() => S.armorText("a\0b")).toThrow();
        expect(() => S.armorText("a".repeat(65 * 1024))).toThrow();
    });
    test("encryptRequest", () => {
        const r = S.encryptRequest({ plaintext: "hi", recipients: [FPR], signWith: null });
        expect(r.signWith).toBeNull();
        expect(() => S.encryptRequest({ plaintext: "", recipients: [FPR], signWith: null })).toThrow();
        expect(() => S.encryptRequest({ plaintext: "hi", recipients: [], signWith: null })).toThrow();
        expect(() => S.encryptRequest({ plaintext: "hi", recipients: [FPR, FPR], signWith: null })).toThrow();
        expect(() => S.encryptRequest({ plaintext: "hi", recipients: [FPR, FPR.replace("2199", "0000"), FPR.replace("2199", "1111")], signWith: null })).not.toThrow();
        const many = Array.from({ length: 17 }, (_, i) => FPR.slice(0, 36) + i.toString(16).toUpperCase().padStart(4, "0"));
        expect(() => S.encryptRequest({ plaintext: "hi", recipients: many.slice(0, 16), signWith: null })).not.toThrow();
        expect(() => S.encryptRequest({ plaintext: "hi", recipients: many, signWith: null })).toThrow();
        expect(() => S.encryptRequest({ plaintext: "hi", recipients: [FPR], signWith: "bad" })).toThrow();
        expect(() => S.encryptRequest("nope")).toThrow();
        expect(() => S.encryptRequest({ plaintext: "hi", recipients: [FPR], signWith: null, __proto__: { x: 1 } })).not.toThrow();
    });
    test("decryptRequest", () => {
        expect(S.decryptRequest({ armored: "x", authorUserId: null }).authorUserId).toBeNull();
        expect(() => S.decryptRequest({ armored: "x", authorUserId: "nope" })).toThrow();
        expect(() => S.decryptRequest({ armored: 5 })).toThrow();
    });
    test("bindRequest sanitises the label", () => {
        const r = S.bindRequest({ userId: "343383572805058560", fingerprint: FPR, userLabel: "al\u0007ice" });
        expect(r.userLabel).toBe("al?ice");
        expect(() => S.bindRequest({ userId: "343383572805058560", fingerprint: FPR, userLabel: "x".repeat(200) })).toThrow();
    });
});

describe("sign / verify schema", () => {
    const FPR = "2199C6B42AEA12C46F78B51EC7C73743035A3ECE";
    test("signRequest limits", () => {
        const ok = S.signRequest({ text: "hello", channelId: "100000000000000001", signWith: FPR });
        expect(ok).toEqual({ text: "hello", channelId: "100000000000000001", signWith: FPR });
        expect(() => S.signRequest({ text: "", channelId: "100000000000000001", signWith: FPR })).toThrow();
        expect(() => S.signRequest({ text: "x".repeat(4001), channelId: "100000000000000001", signWith: FPR })).toThrow();
        expect(() => S.signRequest({ text: "a\u0007b", channelId: "100000000000000001", signWith: FPR })).toThrow();
        expect(() => S.signRequest({ text: "hi", channelId: "100000000000000001", signWith: null })).toThrow();
        expect(() => S.signRequest({ text: "hi", channelId: "nope", signWith: FPR })).toThrow();
        expect(S.signRequest({ text: "tab\tand\nnewline é", channelId: "100000000000000001", signWith: FPR }).text).toContain("é");
    });
    test("verifySignatureRequest variants", () => {
        const d = S.verifySignatureRequest({ kind: "detached", text: "hi", signature: "-----BEGIN PGP SIGNATURE-----\n", channelId: null, authorUserId: null });
        expect(d.kind).toBe("detached");
        const c = S.verifySignatureRequest({ kind: "clearsign", armored: "héllo", channelId: "100000000000000001", authorUserId: "100000000000000002", authorIsSelf: true });
        expect(c).toMatchObject({ kind: "clearsign", authorIsSelf: true });
        expect(() => S.verifySignatureRequest({ kind: "detached", text: "hi", signature: "é", channelId: null, authorUserId: null })).toThrow();
        expect(() => S.verifySignatureRequest({ kind: "other", armored: "x", channelId: null, authorUserId: null })).toThrow();
    });
    test("decryptRequest accepts an optional channelId", () => {
        expect(S.decryptRequest({ armored: "x", authorUserId: null, channelId: "100000000000000001" }).channelId).toBe("100000000000000001");
        expect(() => S.decryptRequest({ armored: "x", authorUserId: null, channelId: "abc" })).toThrow();
    });
});

describe("attachmentUrl (what the main process may download)", () => {
    const good = "https://cdn.discordapp.com/attachments/123456789012345678/987654321098765432/photo.png.gpg?ex=1&is=2&hm=abc";
    it("accepts Discord CDN attachment URLs, query string included", () => {
        expect(S.attachmentUrl(good)).toBe(good);
        expect(S.attachmentUrl("https://media.discordapp.net/attachments/1/2/a.asc")).toContain("media.discordapp.net");
        expect(S.attachmentUrl("https://cdn.discordapp.com/ephemeral-attachments/1/2/a.gpg")).toBeTruthy();
        expect(S.fetchArmoredRequest({ url: good }).url).toBe(good);
    });
    it("rejects other hosts, schemes, ports, credentials and paths", () => {
        for (const bad of [
            "http://cdn.discordapp.com/attachments/1/2/a.gpg",
            "https://cdn.discordapp.com:8443/attachments/1/2/a.gpg",
            "https://user:pw@cdn.discordapp.com/attachments/1/2/a.gpg",
            "https://cdn.discordapp.com.evil.test/attachments/1/2/a.gpg",
            "https://evil.test/attachments/1/2/a.gpg",
            "https://127.0.0.1/attachments/1/2/a.gpg",
            "https://cdn.discordapp.com/avatars/1/2.png",
            "https://cdn.discordapp.com/attachments/1/2/",
            "https://cdn.discordapp.com/attachments/x/2/a.gpg",
            "file:///etc/passwd",
            "",
            42,
            "https://cdn.discordapp.com/attachments/1/2/" + "a".repeat(2100),
        ]) expect(() => S.attachmentUrl(bad as any), String(bad)).toThrow();
    });
    it("decryptAttachment requests carry a URL, not bytes", () => {
        const r = S.decryptAttachmentRequest({ url: good, filename: "../photo.png", authorUserId: null, action: "preview" });
        expect(r.url).toBe(good);
        expect(r.filename).toBe("photo.png");
        expect(() => S.decryptAttachmentRequest({ data: new Uint8Array(4), filename: "a", authorUserId: null, action: "preview" })).toThrow();
    });
});
