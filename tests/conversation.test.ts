import { describe, expect, test } from "vitest";

import { describeConversation, memberKeys, policyFor, recipientFingerprints } from "../core/conversation";
import { Binding } from "../core/types";

const b = (fingerprint: string, userId = "1"): Binding => ({ userId, fingerprint, verified: false, addedAt: 0, changedAt: null, previousFingerprints: [] });
const A = "A".repeat(40), B = "B".repeat(40), ME = "C".repeat(40);

describe("describeConversation", () => {
    test("1:1 DM", () => {
        expect(describeConversation({ id: "c", type: 1, recipients: ["111"] })).toEqual({ kind: "dm", channelId: "c", recipientIds: ["111"] });
    });
    test("group DM keeps every member and de-duplicates", () => {
        expect(describeConversation({ id: "g", type: 3, recipients: ["1", "2", "2", "3"] })).toEqual({ kind: "group", channelId: "g", recipientIds: ["1", "2", "3"] });
    });
    test("guild text channels and threads use the chosen recipient list; voice/forum containers are refused", () => {
        expect(describeConversation({ id: "t", type: 0, recipients: ["1"] })).toEqual({ kind: "guild", channelId: "t", recipientIds: [] });
        expect(describeConversation({ id: "t", type: 11 }, ["5", "5", "6"])).toEqual({ kind: "guild", channelId: "t", recipientIds: ["5", "6"] });
        expect(describeConversation({ id: "v", type: 2 })).toBeNull();
        expect(describeConversation({ id: "f", type: 15 })).toBeNull();
    });
    test("empty groups and malformed DMs are refused", () => {
        expect(describeConversation({ id: "g", type: 3, recipients: [] })).toBeNull();
        expect(describeConversation({ id: "d", type: 1, recipients: [] })).toBeNull();
        expect(describeConversation({ id: "d", type: 1, recipients: ["1", "2"] })).toBeNull();
        expect(describeConversation(null)).toBeNull();
    });
});

describe("memberKeys / recipientFingerprints", () => {
    const bindings: Record<string, Binding> = { "1": b(A, "1"), "2": b(B, "2") };
    const get = (id: string) => bindings[id] ?? null;

    test("complete when every member is bound", () => {
        const k = memberKeys(["1", "2"], get);
        expect(k.complete).toBe(true);
        expect(k.unbound).toEqual([]);
        expect(recipientFingerprints(k, ME)).toEqual([A, B, ME]);
    });
    test("one unbound member makes the set incomplete (fail closed)", () => {
        const k = memberKeys(["1", "9"], get);
        expect(k.complete).toBe(false);
        expect(k.unbound).toEqual(["9"]);
    });
    test("own key and shared keys are not listed twice", () => {
        const k = memberKeys(["1", "2"], id => id === "2" ? b(A, "2") : get(id));
        expect(recipientFingerprints(k, A)).toEqual([A]);
    });
});

describe("policyFor", () => {
    const settings = { encryptByDefault: true, signMessages: true };
    const bound = (id: string) => (id === "1" || id === "2" ? b(A, id) : null);
    const dm = { kind: "dm" as const, channelId: "c", recipientIds: ["1"] };
    const guild = (ids: string[]) => ({ kind: "guild" as const, channelId: "t", recipientIds: ids });

    test("DM: default policy encrypts and signs when the key is bound", () => {
        const p = policyFor(dm, {}, settings, bound);
        expect(p).toMatchObject({ encrypt: true, encryptWanted: true, encryptBlocked: null, sign: true, signExplicit: false });
    });
    test("DM: no binding blocks encryption and signing defaults to off", () => {
        const p = policyFor({ ...dm, recipientIds: ["9"] }, {}, settings, bound);
        expect(p.encrypt).toBe(false);
        expect(p.encryptBlocked).toMatch(/no PGP key/);
        expect(p.sign).toBe(false);
    });
    test("explicit prefs win: encryption off but signing on", () => {
        const p = policyFor(dm, { encrypt: false, sign: true }, settings, bound);
        expect(p).toMatchObject({ encrypt: false, encryptWanted: false, sign: true, signExplicit: true });
    });
    test("guild: never encrypts by default, needs recipients, and all of them bound", () => {
        expect(policyFor(guild(["1"]), {}, settings, bound).encrypt).toBe(false);
        expect(policyFor(guild([]), { encrypt: true }, settings, bound).encryptBlocked).toMatch(/no recipients/);
        expect(policyFor(guild(["1", "9"]), { encrypt: true }, settings, bound).encryptBlocked).toMatch(/no key bound any more/);
        const ok = policyFor(guild(["1", "2"]), { encrypt: true }, settings, bound);
        expect(ok.encrypt).toBe(true);
        expect(ok.sign).toBe(true);
    });
    describe("no silent downgrade (sendBlocked)", () => {
        const group = (ids: string[]) => ({ kind: "group" as const, channelId: "g", recipientIds: ids });

        test("a DM with someone who never had a key stays an ordinary plaintext DM", () => {
            const p = policyFor({ ...dm, recipientIds: ["9"] }, {}, settings, bound);
            expect(p).toMatchObject({ encrypt: false, encryptWanted: true, sendBlocked: null });
        });
        test("nothing is blocked while encryption works", () => {
            expect(policyFor(dm, { encrypt: true, wasEncrypted: true }, settings, bound)).toMatchObject({ encrypt: true, sendBlocked: null });
        });
        test("encryption explicitly on, key gone: blocked instead of plaintext", () => {
            const p = policyFor({ ...dm, recipientIds: ["9"] }, { encrypt: true }, settings, bound);
            expect(p.encrypt).toBe(false);
            expect(p.sendBlocked).toMatch(/no PGP key/);
        });
        test("default-on conversation that already sent encrypted messages: blocked when a key is missing", () => {
            const p = policyFor({ ...dm, recipientIds: ["9"] }, { wasEncrypted: true }, settings, bound);
            expect(p.sendBlocked).toMatch(/no PGP key/);
        });
        test("a member without a key joining an encrypted group blocks sending", () => {
            expect(policyFor(group(["1", "2"]), { wasEncrypted: true }, settings, bound)).toMatchObject({ encrypt: true, sendBlocked: null });
            const p = policyFor(group(["1", "2", "9"]), { wasEncrypted: true }, settings, bound);
            expect(p.encrypt).toBe(false);
            expect(p.sendBlocked).toMatch(/1 member has no PGP key/);
            // ...but a group that was never encrypted is not held hostage by the default policy
            expect(policyFor(group(["1", "2", "9"]), {}, settings, bound).sendBlocked).toBeNull();
        });
        test("turning encryption off explicitly always unblocks", () => {
            const p = policyFor({ ...dm, recipientIds: ["9"] }, { encrypt: false, wasEncrypted: true }, settings, bound);
            expect(p).toMatchObject({ encrypt: false, encryptWanted: false, sendBlocked: null });
        });
        test("guild channel: chosen recipient lost their binding, or no recipients left", () => {
            expect(policyFor(guild(["1", "9"]), { encrypt: true }, settings, bound).sendBlocked).toMatch(/no key bound any more/);
            expect(policyFor(guild([]), { encrypt: true }, settings, bound).sendBlocked).toMatch(/no recipients/);
            expect(policyFor(guild(["1", "9"]), {}, settings, bound).sendBlocked).toBeNull();
            // encryption switched off for the channel: an old wasEncrypted marker alone does not block
            expect(policyFor(guild(["1", "9"]), { wasEncrypted: true }, settings, bound).sendBlocked).toBeNull();
        });
        test("bindings not loaded: every conversation that wants encryption is blocked, never sent in the clear", () => {
            const none = () => null;
            const p = policyFor(dm, {}, settings, none, false);
            expect(p.encrypt).toBe(false);
            expect(p.sendBlocked).toMatch(/could not load your key bindings/);
            expect(policyFor(group(["1", "2"]), {}, settings, none, false).sendBlocked).toMatch(/could not load/);
            expect(policyFor(guild(["1"]), { encrypt: true }, settings, none, false).sendBlocked).toMatch(/could not load/);
            // conversations that do not want encryption are unaffected
            expect(policyFor(dm, { encrypt: false }, settings, none, false).sendBlocked).toBeNull();
            expect(policyFor(dm, {}, { ...settings, encryptByDefault: false }, none, false).sendBlocked).toBeNull();
            expect(policyFor(guild(["1"]), {}, settings, none, false).sendBlocked).toBeNull();
        });
        test("signing falls back to off while blocked, so a blocked message can never go out clearsigned by default", () => {
            expect(policyFor({ ...dm, recipientIds: ["9"] }, { encrypt: true }, settings, bound).sign).toBe(false);
        });
    });

    test("signMessages=false turns the encrypted default off too", () => {
        expect(policyFor(dm, {}, { ...settings, signMessages: false }, bound).sign).toBe(false);
    });
});
