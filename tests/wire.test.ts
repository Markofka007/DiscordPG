import { readFileSync } from "fs";
import { describe, expect, test } from "vitest";

import { ARMOR_MAX_BYTES } from "../core/types";
import { discordContentLimit, extractArmor, extractDetachedSigned, fnv1a64, isEncryptedMessage, isPublicKeyBlock, parseArmor, wrapForDiscord } from "../core/wire";

/** The wire form older DiscordPG versions used for detached-signed messages: text, newline, signature block. */
const wrapDetached = (text: string, signatureArmored: string, codeBlock: boolean) => `${text.trim()}\n${wrapForDiscord(signatureArmored, codeBlock)}`;

const MSG = readFileSync(new URL("./fixtures/message.asc", import.meta.url), "utf8");
const CLEAR = readFileSync(new URL("./fixtures/clearsigned.asc", import.meta.url), "utf8");
const DETACHED = readFileSync(new URL("./fixtures/detached.sig.asc", import.meta.url), "utf8");

describe("parseArmor", () => {
    test("accepts a canonical gpg message", () => {
        const r = parseArmor(MSG);
        expect(r?.kind).toBe("MESSAGE");
        expect(r?.armored).toBe(MSG);
    });
    test("normalises CRLF and trailing whitespace", () => {
        const r = parseArmor(MSG.replace(/\n/g, "  \r\n"));
        expect(r?.armored).toBe(MSG);
    });
    test("accepts armor headers and strips them from the canonical form", () => {
        const withHeaders = MSG.replace("-----\n\n", "-----\nVersion: GnuPG v2\nComment: hi there\n\n");
        expect(parseArmor(withHeaders)?.kind).toBe("MESSAGE");
        expect(parseArmor(withHeaders)?.armored).toBe(MSG);
    });
    test("tolerates Kleopatra-style headers: TAB separators, Unicode user IDs, empty values", () => {
        const kleo = MSG.replace("-----\n\n", "-----\nComment: User-ID:\tJosé Müller <jose@example.org>\nComment: Created:\t2026-01-02 03:04\nComment:\nComment: Fingerprint:\tABCD 1234\n\n");
        expect(parseArmor(kleo)?.armored).toBe(MSG);
        expect(extractArmor("```\n" + kleo + "```")?.armored).toBe(MSG);
    });
    test("still rejects control characters and junk inside headers", () => {
        expect(parseArmor(MSG.replace("-----\n\n", "-----\nComment: a\u0007b\n\n"))).toBeNull();
        expect(parseArmor(MSG.replace("-----\n\n", "-----\nnot a header\n\n"))).toBeNull();
    });
    test("rejects wrong kind when expectKind is given", () => {
        expect(parseArmor(MSG, "PUBLIC KEY BLOCK")).toBeNull();
    });
    test("rejects private key blocks", () => {
        const pk = MSG.replace(/PGP MESSAGE/g, "PGP PRIVATE KEY BLOCK");
        expect(parseArmor(pk)).toBeNull();
    });
    test("rejects truncated / mismatched footer", () => {
        expect(parseArmor(MSG.replace("-----END PGP MESSAGE-----", ""))).toBeNull();
        expect(parseArmor(MSG.replace("-----END PGP MESSAGE-----", "-----END PGP SIGNATURE-----"))).toBeNull();
    });
    test("rejects non-base64 body lines and junk after CRC", () => {
        expect(parseArmor(MSG.replace("=vieu", "=vieu\nhello"))).toBeNull();
        expect(parseArmor(MSG.replace("hF4D+c/a", "hF4D+c/@"))).toBeNull();
    });
    test("rejects empty body", () => {
        expect(parseArmor("-----BEGIN PGP MESSAGE-----\n\n-----END PGP MESSAGE-----\n")).toBeNull();
    });
    test("rejects non-ASCII and oversize input", () => {
        expect(parseArmor(MSG.replace("hF4D", "hF4Dé"))).toBeNull();
        expect(parseArmor("-----BEGIN PGP MESSAGE-----\n\n" + "A".repeat(ARMOR_MAX_BYTES) + "\n-----END PGP MESSAGE-----\n")).toBeNull();
    });
    test("rejects padding in the middle of the body", () => {
        const bad = MSG.replace("FPkFTXBNuKMzb79h6CLbSSFSRxaZyc0VhSTDwdtkhBccQBvU96PtnB7m7+PBHZqU", "FPkFTXBNuKMzb79h6CLbSSFSRxaZyc0VhSTDwdtkhBccQBvU96PtnB7m7+PBHZ==");
        expect(parseArmor(bad)).toBeNull();
    });
});

describe("extractArmor", () => {
    test("finds a bare block", () => {
        const r = extractArmor(MSG);
        expect(r?.armored).toBe(MSG);
        expect(r?.start).toBe(0);
    });
    test("finds a fenced block with and without a language tag", () => {
        expect(extractArmor(wrapForDiscord(MSG, true))?.armored).toBe(MSG);
        expect(extractArmor("```asc\n" + MSG + "```")?.armored).toBe(MSG);
        expect(extractArmor("  \n```\n" + MSG + "```\n ")?.armored).toBe(MSG);
    });
    test("refuses a block embedded in other text", () => {
        expect(extractArmor("look at this:\n" + MSG)).toBeNull();
        expect(extractArmor(MSG + "\ntrailing commentary")).toBeNull();
        expect(extractArmor("```\n" + MSG + "```\nmore")).toBeNull();
    });
    test("refuses two blocks", () => {
        expect(extractArmor(MSG + MSG)).toBeNull();
    });
    test("kind helpers", () => {
        expect(isEncryptedMessage(MSG)).toBe(true);
        expect(isPublicKeyBlock(MSG)).toBe(false);
        expect(isEncryptedMessage("hello")).toBe(false);
    });
});

describe("misc", () => {
    test("wrapForDiscord round-trips", () => {
        expect(wrapForDiscord(MSG, false)).toBe(MSG.slice(0, -1));
        expect(wrapForDiscord(MSG, true).startsWith("```\n-----BEGIN")).toBe(true);
    });
    test("content limit", () => {
        expect(discordContentLimit(0)).toBe(2000);
        expect(discordContentLimit(null)).toBe(2000);
        expect(discordContentLimit(2)).toBe(4000);
        expect(discordContentLimit(3)).toBe(2000); // Nitro Basic
    });
    test("fnv1a64 is stable and 16 hex chars", () => {
        expect(fnv1a64("")).toBe("cbf29ce484222325");
        expect(fnv1a64("a")).toBe("af63dc4c8601ec8c");
        expect(fnv1a64(MSG)).toMatch(/^[0-9a-f]{16}$/);
    });
});

describe("cleartext signature framework", () => {
    test("accepts gpg's clearsigned output, with UTF-8 and dash-escaped text", () => {
        const r = parseArmor(CLEAR);
        expect(r?.kind).toBe("SIGNED MESSAGE");
        expect(r?.armored).toBe(CLEAR);
        expect(parseArmor(CLEAR, "SIGNED MESSAGE")).not.toBeNull();
        expect(parseArmor(CLEAR, "MESSAGE")).toBeNull();
        expect(extractArmor("```\n" + CLEAR + "```")?.kind).toBe("SIGNED MESSAGE");
    });
    test("detached signatures parse as SIGNATURE", () => {
        expect(parseArmor(DETACHED)?.kind).toBe("SIGNATURE");
        expect(parseArmor(DETACHED, "SIGNATURE")?.armored).toBe(DETACHED);
    });
    test("rejects a clearsign frame with no text, control characters, a raw armor line inside the text, or a broken signature", () => {
        expect(parseArmor(CLEAR.replace(/\n\nh.*?\n- - item one\n- - item two\n/s, "\n\n"))).toBeNull();
        expect(parseArmor(CLEAR.replace("héllo", "h\u0007llo"))).toBeNull();
        expect(parseArmor(CLEAR.replace("- - item one", "-----BEGIN PGP MESSAGE-----"))).toBeNull();
        expect(parseArmor(CLEAR.replace("=Nnin", "=Nni!"))).toBeNull();
        expect(parseArmor(CLEAR.replace("-----END PGP SIGNATURE-----", "-----END PGP MESSAGE-----"))).toBeNull();
        expect(parseArmor(CLEAR.replace("Hash: SHA512\n", "Hash SHA512\n"))).toBeNull();
    });
    test("a bare BEGIN PGP SIGNED MESSAGE line without a signature is not a block", () => {
        expect(parseArmor("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nhello\n")).toBeNull();
    });
});

describe("extractDetachedSigned (text followed by a PGP SIGNATURE block)", () => {
    test("bare and fenced signature blocks, with the text trimmed", () => {
        const bare = extractDetachedSigned("hello world\n" + DETACHED);
        expect(bare).toEqual({ text: "hello world", signature: DETACHED });
        const fenced = extractDetachedSigned(wrapDetached("  hello world \n", DETACHED, true));
        expect(fenced).toEqual({ text: "hello world", signature: DETACHED });
        expect(extractDetachedSigned("hi\n```asc\n" + DETACHED + "```")).toEqual({ text: "hi", signature: DETACHED });
        expect(extractDetachedSigned(wrapDetached("hello", DETACHED, false))).toEqual({ text: "hello", signature: DETACHED });
    });
    test("multi-line text keeps its inner newlines and the LAST signature block wins", () => {
        const text = "line one\n\nline two with -----BEGIN PGP SIGNATURE----- inside";
        expect(extractDetachedSigned(wrapDetached(text, DETACHED, true))?.text).toBe(text);
    });
    test("rejects a lone signature, missing text, a broken block, or trailing junk", () => {
        expect(extractDetachedSigned(DETACHED)).toBeNull();
        expect(extractDetachedSigned("```\n" + DETACHED + "```")).toBeNull();
        expect(extractDetachedSigned("hi\n" + DETACHED.replace("-----END PGP SIGNATURE-----", ""))).toBeNull();
        expect(extractDetachedSigned("hi\n" + DETACHED + "trailing")).toBeNull();
        expect(extractDetachedSigned("hi\n" + MSG)).toBeNull();
        expect(extractDetachedSigned("x".repeat(4001) + "\n" + DETACHED)).toBeNull();
    });
    test("an ordinary message or an encrypted message is not detached-signed", () => {
        expect(extractDetachedSigned("just text")).toBeNull();
        expect(extractDetachedSigned(MSG)).toBeNull();
        expect(extractArmor(wrapDetached("hi", DETACHED, true))).toBeNull();
    });
});
