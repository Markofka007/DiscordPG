import { readFileSync } from "fs";
import { describe, expect, test } from "vitest";

import { channelMismatch, classifyErrCode, extractSignature, findFailure, gpgErrCode, interpretDecrypt, interpretDetachedVerify, interpretEncrypt, interpretImport, interpretImportPreview, interpretSign, interpretVerify, parseStatusLines, RunOutcome, unescapeStatus } from "../native/status";

const fx = (n: string) => readFileSync(new URL(`./fixtures/${n}`, import.meta.url), "utf8");
const run = (stderr: string, exitCode = 0, stdout = "hello **bob** <@123>\n"): RunOutcome => ({ exitCode, signal: null, timedOut: false, stdout, stderr });

describe("parseStatusLines", () => {
    test("ignores human-readable lines and keeps args", () => {
        const ev = parseStatusLines(fx("decrypt-good-signed.status"));
        expect(ev.every(e => !e.keyword.startsWith("gpg:"))).toBe(true);
        const good = ev.find(e => e.keyword === "GOODSIG")!;
        expect(good.args[0]).toBe("CD678B24E3DCF45B");
        expect(good.rest).toBe("CD678B24E3DCF45B Alice Test <alice@example.invalid>");
    });
});

describe("error codes", () => {
    test("libgpg-error packing", () => {
        expect(gpgErrCode(33554449)).toBe(17);
        expect(classifyErrCode(33554449)).toBe("not-for-you");
        expect(classifyErrCode(83886179)).toBe("pin-cancelled"); // agent | CANCELED
        expect(classifyErrCode((5 << 24) | 11)).toBe("pin-cancelled");
        expect(classifyErrCode((5 << 24) | 104)).toBe("card-missing");
        expect(classifyErrCode(33554433)).toBeNull(); // GENERAL
    });
});

describe("interpretDecrypt", () => {
    test("good signed message", () => {
        const r = interpretDecrypt(run(fx("decrypt-good-signed.status")));
        expect(r.ok).toBe(true);
        if (!r.ok) return;
        expect(r.value.plaintext).toBe("hello **bob** <@123>\n");
        expect(r.value.encryptedTo).toEqual(["F9CFDAA170CAB048", "DB5C65F56A91E810"]);
        expect(r.value.signature).toEqual({
            status: "good",
            fingerprint: "3B7C53074B054F10F2E088DCCD678B24E3DCF45B",
            primaryFingerprint: "2199C6B42AEA12C46F78B51EC7C73743035A3ECE",
            timestamp: 1794288831,
        });
    });
    test("unsigned message", () => {
        const r = interpretDecrypt(run(fx("decrypt-unsigned.status"), 0, "nosig\n"));
        expect(r.ok && r.value.signature.status).toBe("none");
    });
    test("not for you", () => {
        const r = interpretDecrypt(run(fx("decrypt-not-for-you.status"), 2, ""));
        expect(r).toMatchObject({ ok: false, error: "not-for-you" });
    });
    test("NODATA with DECRYPTION_OKAY but non-zero exit is not a success", () => {
        const r = interpretDecrypt(run(fx("decrypt-nodata.status"), 2, "partial"));
        expect(r.ok).toBe(false);
    });
    test("DECRYPTION_OKAY but exit code 2 is not a success", () => {
        const r = interpretDecrypt(run(fx("decrypt-good-signed.status"), 2));
        expect(r.ok).toBe(false);
    });
    test("BADSIG is tampered even if decryption worked", () => {
        const s = fx("decrypt-good-signed.status").replace("GOODSIG", "BADSIG");
        expect(interpretDecrypt(run(s))).toMatchObject({ ok: false, error: "tampered" });
    });
    test("ERRSIG (unknown key) is reported, not fatal", () => {
        const s = fx("decrypt-good-signed.status")
            .replace(/\[GNUPG:\] GOODSIG.*\n/, "[GNUPG:] ERRSIG CD678B24E3DCF45B 22 10 00 1794288831 9 3B7C53074B054F10F2E088DCCD678B24E3DCF45B\n")
            .replace(/\[GNUPG:\] VALIDSIG.*\n/, "");
        const r = interpretDecrypt(run(s));
        expect(r.ok && r.value.signature).toEqual({ status: "unknown-key", keyId: "CD678B24E3DCF45B" });
    });
    test("two signatures are refused", () => {
        const s = fx("decrypt-good-signed.status");
        const sigBlock = s.slice(s.indexOf("[GNUPG:] NEWSIG"), s.indexOf("[GNUPG:] TRUST_ULTIMATE"));
        const doubled = s.replace("[GNUPG:] TRUST_ULTIMATE", sigBlock + "[GNUPG:] TRUST_ULTIMATE");
        expect(extractSignature(parseStatusLines(doubled)).status).toBe("bad");
    });
    test("card problems", () => {
        expect(findFailure(parseStatusLines("[GNUPG:] CARDCTRL 4\n[GNUPG:] DECRYPTION_FAILED\n"))).toMatchObject({ error: "card-missing" });
        expect(findFailure(parseStatusLines("[GNUPG:] SC_OP_FAILURE 2\n[GNUPG:] FAILURE pkdecrypt 33554433\n"))).toMatchObject({ error: "card-missing" });
    });
    test("pinentry cancelled", () => {
        const s = "[GNUPG:] PINENTRY_LAUNCHED 123 gnome3 1.2 - - - 0/0 -\n[GNUPG:] ERROR pkdecrypt_failed 83886179\n[GNUPG:] DECRYPTION_FAILED\n";
        expect(interpretDecrypt(run(s, 2, ""))).toMatchObject({ ok: false, error: "pin-cancelled" });
    });
    test("timeout wins", () => {
        expect(interpretDecrypt({ ...run(""), timedOut: true })).toMatchObject({ ok: false, error: "timeout" });
    });
});

describe("interpretEncrypt", () => {
    const armored = "-----BEGIN PGP MESSAGE-----\n\nAAAA\n=abcd\n-----END PGP MESSAGE-----\n";
    test("signed success", () => {
        expect(interpretEncrypt(run(fx("encrypt-signed.status"), 0, armored), true)).toEqual({ ok: true, signed: true });
    });
    test("expected signature missing", () => {
        const s = fx("encrypt-signed.status").replace(/\[GNUPG:\] SIG_CREATED.*\n/, "");
        expect(interpretEncrypt(run(s, 0, armored), true).ok).toBe(false);
        expect(interpretEncrypt(run(s, 0, armored), false)).toEqual({ ok: true, signed: false });
    });
    test("invalid recipient", () => {
        expect(interpretEncrypt(run("[GNUPG:] INV_RECP 0 ABCDEF\n[GNUPG:] FAILURE encrypt 33554433\n", 2, ""), false)).toMatchObject({ ok: false, error: "invalid-recipient" });
    });
    test("revoked key", () => {
        expect(interpretEncrypt(run("[GNUPG:] KEYREVOKED\n[GNUPG:] INV_RECP 4 ABCDEF\n", 2, ""), false)).toMatchObject({ ok: false, error: "key-revoked" });
    });
});

describe("interpretEncrypt: only the requested keys may be used", () => {
    const A = "85DA5C035651B99490158A8D9EFBFCEA20491EA7";
    const B = "E024354246316F73E3A58083179FC7D2044E9D34";
    const IMPOSTOR = "0DC28D96CD804C19DC496C39248E4C5D8BCD9A76";
    const armored = "-----BEGIN PGP MESSAGE-----\n\nabc\n-----END PGP MESSAGE-----\n";
    const status = (...considered: string[]) =>
        considered.map(f => `[GNUPG:] KEY_CONSIDERED ${f} 0\n`).join("") + "[GNUPG:] BEGIN_ENCRYPTION 0 9 2\n[GNUPG:] END_ENCRYPTION\n";

    test("recipients and signer are accepted, in any order and repeated", () => {
        expect(interpretEncrypt(run(status(A, A, B), 0, armored), false, true, [B, A])).toEqual({ ok: true, signed: false });
    });
    test("a key that was not requested fails closed, even though gpg reported success", () => {
        expect(interpretEncrypt(run(status(A, IMPOSTOR), 0, armored), false, true, [A, B])).toMatchObject({ ok: false, error: "ambiguous-key" });
        expect(interpretEncrypt(run(status(IMPOSTOR), 0, armored), false, true, [B])).toMatchObject({ ok: false, error: "ambiguous-key" });
    });
    test("a malformed KEY_CONSIDERED line is not waved through", () => {
        expect(interpretEncrypt(run("[GNUPG:] KEY_CONSIDERED\n" + status(A), 0, armored), false, true, [A])).toMatchObject({ ok: false, error: "ambiguous-key" });
    });
    test("without an expectation the check is off (callers that do not encrypt to named keys)", () => {
        expect(interpretEncrypt(run(status(IMPOSTOR), 0, armored), false)).toEqual({ ok: true, signed: false });
    });
});

describe("interpretImportPreview", () => {
    const out = (stdout: string, exitCode = 0): RunOutcome => ({ exitCode, signal: null, timedOut: false, stdout, stderr: "" });
    const pub = "pub:-:255:22:248E4C5D8BCD9A76:1780272000:::-:::scESC::::::ed25519:::0:\nfpr:::::::::0DC28D96CD804C19DC496C39248E4C5D8BCD9A76:\nuid:-::::1780272000::X::Mallory::::::::::0:\nsub:-:255:18:3808DF142C09DD91:1780272000::::::e::::::cv25519::\n";
    test("public keys only: allowed", () => {
        expect(interpretImportPreview(out(pub))).toEqual({ ok: true });
    });
    test("a secret primary key is refused", () => {
        expect(interpretImportPreview(out(pub.replace(/^pub:/, "sec:")))).toMatchObject({ ok: false, error: "secret-key-block" });
    });
    test("a secret subkey is refused, also next to public keys", () => {
        expect(interpretImportPreview(out(pub.replace(/^sub:/m, "ssb:")))).toMatchObject({ ok: false, error: "secret-key-block" });
        expect(interpretImportPreview(out(pub + pub.replace(/^pub:/, "sec:")))).toMatchObject({ ok: false, error: "secret-key-block" });
    });
    test("no key at all, a failed listing or a timeout never count as safe", () => {
        expect(interpretImportPreview(out(""))).toMatchObject({ ok: false, error: "malformed" });
        expect(interpretImportPreview(out(pub, 2))).toMatchObject({ ok: false, error: "malformed" });
        expect(interpretImportPreview({ ...out(pub), timedOut: true })).toMatchObject({ ok: false, error: "timeout" });
    });
});

describe("interpretImport", () => {
    test("success", () => {
        const s = "[GNUPG:] IMPORT_OK 0 E024354246316F73E3A58083179FC7D2044E9D34\n[GNUPG:] IMPORT_RES 1 0 0 0 1 0 0 0 0 0 0 0 0 0 0\n";
        expect(interpretImport(run(s, 0, ""))).toEqual({ ok: true, fingerprints: ["E024354246316F73E3A58083179FC7D2044E9D34"] });
    });
    test("secret key material is refused", () => {
        const s = "[GNUPG:] IMPORT_OK 17 E024354246316F73E3A58083179FC7D2044E9D34\n[GNUPG:] IMPORT_RES 1 0 1 0 0 0 0 0 0 1 1 0 0 0 0\n";
        expect(interpretImport(run(s, 0, ""))).toMatchObject({ ok: false, error: "secret-key-block" });
    });
    test("nothing imported", () => {
        expect(interpretImport(run("[GNUPG:] IMPORT_RES 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n", 2, "")).ok).toBe(false);
    });
});

describe("sign-only status handling", () => {
    const FPR = "85DA5C035651B99490158A8D9EFBFCEA20491EA7";
    test("clearsign verification: signed mode, notation captured, channel mismatch detected", () => {
        const r = interpretVerify(run(fx("verify-clearsign.status"), 0, "héllo **bob**\r\n- item one\r\n- item two\r\n"));
        expect(r.ok).toBe(true);
        if (!r.ok) return;
        expect(r.value.mode).toBe("signed");
        expect(r.value.plaintext).toBe("héllo **bob**\n- item one\n- item two\n");
        expect(r.value.signature).toMatchObject({ status: "good", primaryFingerprint: FPR, notations: { "channel@discordpg.invalid": "123456789012345678" } });
        expect(channelMismatch(r.value.signature, "123456789012345678")).toBe(false);
        expect(channelMismatch(r.value.signature, "999")).toBe(true);
        expect(channelMismatch(r.value.signature, null)).toBe(false);
        expect(channelMismatch({ status: "none" }, "1")).toBe(false);
    });
    test("verify refuses encrypted input; decrypt reports signed mode for sign-only blocks", () => {
        expect(interpretVerify(run(fx("decrypt-good-signed.status")))).toMatchObject({ ok: false, error: "malformed" });
        const d = interpretDecrypt(run(fx("verify-clearsign.status")));
        expect(d.ok && d.value.mode).toBe("signed");
    });
    test("an unencrypted, unsigned literal is malformed, not a message", () => {
        expect(interpretDecrypt(run("[GNUPG:] PLAINTEXT 62 0 \n", 0))).toMatchObject({ ok: false, error: "malformed" });
    });
    test("detached verification", () => {
        const r = interpretDetachedVerify(run(fx("verify-detached.status"), 0, ""));
        expect(r.ok && r.signature.status).toBe("good");
        expect(interpretDetachedVerify(run("[GNUPG:] NODATA 1\n", 2, ""))).toMatchObject({ ok: false, error: "malformed" });
        expect(interpretDetachedVerify(run("[GNUPG:] NEWSIG\n[GNUPG:] BADSIG 9EFBFCEA20491EA7 Fx\n", 1, ""))).toMatchObject({ ok: false, error: "tampered" });
    });
    test("ERRSIG with exit 2 is an unknown-signer verdict for both encrypted and signed-only input", () => {
        const enc = interpretDecrypt(run(fx("decrypt-good-signed.status").replace(/GOODSIG.*\n/, "ERRSIG CD678B24E3DCF45B 22 10 00 1700000000 9 -\n").replace(/VALIDSIG.*\n/, ""), 2));
        expect(enc.ok && enc.value.signature.status).toBe("unknown-key");
    });
    test("signing status", () => {
        expect(interpretSign(run(fx("sign-clearsign.status"), 0, "-----BEGIN PGP SIGNED MESSAGE-----"))).toEqual({ ok: true });
        expect(interpretSign(run("[GNUPG:] KEY_CONSIDERED X 2\n", 2, ""))).toMatchObject({ ok: false, error: "gpg-error" });
        expect(interpretSign(run("[GNUPG:] PINENTRY_LAUNCHED 1\n[GNUPG:] FAILURE sign 83886179\n", 2, ""))).toMatchObject({ ok: false, error: "pin-cancelled" });
    });
    test("percent unescaping", () => {
        expect(unescapeStatus("a%25b%0Ac")).toBe("a%b\nc");
    });
});
