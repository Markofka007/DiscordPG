import { describe, expect, test } from "vitest";

import { formatBytes, isImageName, isPgpFileName, looksArmored, sniffImage, strippedName } from "../core/files";
import * as S from "../native/schema";

describe("attachment name helpers", () => {
    test("pgp file names and stripping", () => {
        expect(isPgpFileName("photo.png.gpg")).toBe(true);
        expect(isPgpFileName("notes.txt.ASC")).toBe(true);
        expect(isPgpFileName("photo.png")).toBe(false);
        expect(strippedName("photo.png.gpg")).toBe("photo.png");
        expect(strippedName(".gpg")).toBe("attachment");
        expect(isImageName(strippedName("a.JPG.pgp"))).toBe(true);
        expect(isImageName("a.pdf")).toBe(false);
    });
    test("formatBytes", () => {
        expect(formatBytes(10)).toBe("10 B");
        expect(formatBytes(2048)).toBe("2.0 KB");
        expect(formatBytes(3 * 1024 * 1024)).toBe("3.0 MB");
    });
    test("sniffImage recognises png/jpeg/gif/webp only", () => {
        expect(sniffImage(new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0]))).toBe("image/png");
        expect(sniffImage(new Uint8Array([0xff, 0xd8, 0xff, 0xe0]))).toBe("image/jpeg");
        expect(sniffImage(new Uint8Array([...Buffer.from("GIF89a")]))).toBe("image/gif");
        expect(sniffImage(new Uint8Array([...Buffer.from("RIFF\0\0\0\0WEBPVP8 ")]))).toBe("image/webp");
        expect(sniffImage(new Uint8Array([...Buffer.from("%PDF-1.7")]))).toBeNull();
        expect(sniffImage(new Uint8Array([]))).toBeNull();
    });
    test("looksArmored", () => {
        expect(looksArmored(new Uint8Array(Buffer.from("-----BEGIN PGP MESSAGE-----\n")))).toBe(true);
        expect(looksArmored(new Uint8Array([0x85, 0x01, 0x0c]))).toBe(false);
    });
});

describe("attachment schema", () => {
    const FPR = "2199C6B42AEA12C46F78B51EC7C73743035A3ECE";
    test("bytes accepts Uint8Array / ArrayBuffer within the cap", () => {
        expect(S.bytes(new Uint8Array([1, 2]), 10, "d")).toHaveLength(2);
        expect(S.bytes(new ArrayBuffer(4), 10, "d")).toHaveLength(4);
        expect(() => S.bytes("AQI=", 10, "d")).toThrow(S.ValidationError);
        expect(() => S.bytes(new Uint8Array(0), 10, "d")).toThrow();
        expect(() => S.bytes(new Uint8Array(11), 10, "d")).toThrow();
    });
    test("safeFilename neutralises traversal and control characters", () => {
        expect(S.safeFilename("photo.png")).toBe("photo.png");
        expect(S.safeFilename("../../etc/passwd")).toBe("passwd");
        expect(S.safeFilename("C:\\Users\\x\\evil.exe")).toBe("evil.exe");
        expect(S.safeFilename(".hidden")).toBe("hidden");
        expect(S.safeFilename("..")).toBe("attachment");
        expect(S.safeFilename("a\u001fb\u007fc.txt")).toBe("abc.txt");
        expect(() => S.safeFilename("a\u0000b")).toThrow();
        expect(S.safeFilename("   ")).toBe("attachment");
        expect(() => S.safeFilename("x".repeat(256))).toThrow();
        expect(() => S.safeFilename(5)).toThrow();
    });
    test("encryptAttachmentRequest / decryptAttachmentRequest", () => {
        const data = new Uint8Array([1, 2, 3]);
        const e = S.encryptAttachmentRequest({ data, filename: "a.png", recipients: [FPR], signWith: null });
        expect(e.filename).toBe("a.png");
        expect(() => S.encryptAttachmentRequest({ data: "abc", filename: "a", recipients: [FPR], signWith: null })).toThrow();
        const url = "https://cdn.discordapp.com/attachments/1/2/a.png.gpg";
        const d = S.decryptAttachmentRequest({ url, filename: "a.png.gpg", authorUserId: "100000000000000001", authorIsSelf: false, action: "preview" });
        expect(d.action).toBe("preview");
        expect(() => S.decryptAttachmentRequest({ url, filename: "a", authorUserId: null, action: "exec" })).toThrow();
    });
});
