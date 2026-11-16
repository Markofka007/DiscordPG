import { describe, expect, test } from "vitest";

import { decodeGpgconf, isUnderProtectedRoot, windowsProtectedRoots } from "../native/gpg";

describe("Windows gpg path rules (pure helpers, run on every platform)", () => {
    const env = { ProgramFiles: "C:\\Program Files", "ProgramFiles(x86)": "C:\\Program Files (x86)", ProgramW6432: "C:\\Program Files", SystemRoot: "C:\\WINDOWS" };
    const roots = windowsProtectedRoots(env);

    test("roots are normalised and de-duplicated", () => {
        expect(roots).toEqual(["c:\\program files\\", "c:\\program files (x86)\\", "c:\\windows\\"]);
    });
    test("Gpg4win default locations are accepted, case-insensitively and with forward slashes", () => {
        expect(isUnderProtectedRoot("C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe", roots)).toBe(true);
        expect(isUnderProtectedRoot("c:/program files/gnupg/bin/gpg.exe", roots)).toBe(true);
    });
    test("per-user and look-alike locations are refused", () => {
        expect(isUnderProtectedRoot("C:\\Users\\x\\scoop\\apps\\gpg\\current\\bin\\gpg.exe", roots)).toBe(false);
        expect(isUnderProtectedRoot("C:\\Program FilesEvil\\gpg.exe", roots)).toBe(false);
        expect(isUnderProtectedRoot("D:\\Program Files\\GnuPG\\bin\\gpg.exe", roots)).toBe(false);
    });
    test("no roots in the environment means nothing is accepted", () => {
        expect(windowsProtectedRoots({})).toEqual([]);
        expect(isUnderProtectedRoot("C:\\Program Files\\GnuPG\\bin\\gpg.exe", [])).toBe(false);
    });
    test("gpgconf percent escapes are decoded", () => {
        expect(decodeGpgconf("C%3a\\Program Files (x86)\\GnuPG\\bin")).toBe("C:\\Program Files (x86)\\GnuPG\\bin");
        expect(decodeGpgconf("/usr/bin")).toBe("/usr/bin");
    });
});
