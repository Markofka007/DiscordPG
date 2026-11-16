import { readFileSync } from "fs";
import { describe, expect, test } from "vitest";

import { canEncryptTo, isLargeAlgo, parseKeyListing, unescapeColonField, usesCard } from "../native/colons";

const fx = (n: string) => readFileSync(new URL(`./fixtures/${n}`, import.meta.url), "utf8");

describe("parseKeyListing", () => {
    test("secret keys with card stubs", () => {
        const keys = parseKeyListing(fx("secret-keys.colons"));
        expect(keys).toHaveLength(2);
        const card = keys[0];
        expect(card.fingerprint).toBe("32929ADF5FE601064905B7B4A029AA00B5C264E8");
        expect(card.algoName).toBe("EdDSA");
        expect(card.curve).toBe("ed25519");
        expect(card.capabilities).toBe("c");
        expect(card.cardSerial).toBe("#"); // offline primary
        expect(card.uids[0].uid).toBe("Card User <card@example.invalid>");
        expect(card.subkeys).toHaveLength(3);
        expect(card.subkeys[0]).toMatchObject({ capabilities: "e", cardSerial: "D2760001240100000006123456780000", curve: "cv25519", expires: 1857868289 });
        expect(usesCard(card, "e")).toBe(true);
        expect(usesCard(card, "s")).toBe(true);
        expect(canEncryptTo(card)).toBe(true);

        const alice = keys[1];
        expect(alice.cardSerial).toBe("+");
        expect(usesCard(alice, "e")).toBe(false);
        expect(alice.subkeys.map(s => s.fingerprint)).toEqual([
            "9D1CD4D1D7339081926C0098DB5C65F56A91E810",
            "3B7C53074B054F10F2E088DCCD678B24E3DCF45B",
        ]);
    });
    test("public keys incl. a revoked RSA key", () => {
        const keys = parseKeyListing(fx("public-key.colons"));
        expect(keys).toHaveLength(2);
        expect(keys[0].fingerprint).toBe("E024354246316F73E3A58083179FC7D2044E9D34");
        expect(keys[0].cardSerial).toBeNull();
        expect(isLargeAlgo(keys[0])).toBe(false);
        const rsa = keys[1];
        expect(rsa.revoked).toBe(true);
        expect(rsa.algoName).toBe("RSA");
        expect(rsa.bits).toBe(4096);
        expect(isLargeAlgo(rsa)).toBe(true);
        expect(canEncryptTo(rsa)).toBe(false);
    });
    test("expired subkey cannot be encrypted to", () => {
        const text = fx("public-key.colons").split("\n").slice(0, 8).join("\n")
            .replace("sub:u:255:18:F9CFDAA170CAB048:1794288823::", "sub:e:255:18:F9CFDAA170CAB048:1794288823:1700000000");
        const [bob] = parseKeyListing(text);
        expect(canEncryptTo(bob)).toBe(false);
    });
    test("uid unescaping", () => {
        expect(unescapeColonField("a\\x3ab")).toBe("a:b");
    });
    test("garbage is ignored", () => {
        expect(parseKeyListing("")).toEqual([]);
        expect(parseKeyListing("fpr:::::::::ZZZ:\nuid:x\n")).toEqual([]);
    });
});
