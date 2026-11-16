import { mkdtemp, readFile, rm, stat, writeFile } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { BindingStore } from "../native/bindings";

const A = "2199C6B42AEA12C46F78B51EC7C73743035A3ECE";
const B = "E024354246316F73E3A58083179FC7D2044E9D34";
const U = "343383572805058560";

let dir: string;
beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), "discordpg-bind-")); });
afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

describe("BindingStore", () => {
    test("bind, persist with 0600, reload", async () => {
        const path = join(dir, "sub", "bindings.json");
        const s = new BindingStore(path);
        await s.load();
        const b = await s.bind(U, A);
        expect(b).toMatchObject({ userId: U, fingerprint: A, verified: false, changedAt: null });
        const mode = (await stat(path)).mode & 0o777;
        expect(mode).toBe(0o600);

        const s2 = new BindingStore(path);
        await s2.load();
        expect(s2.get(U)?.fingerprint).toBe(A);
        expect([...s2.trustedFingerprints()]).toEqual([A]);
    });
    test("rebinding records history and drops verified", async () => {
        const s = new BindingStore(join(dir, "b.json"));
        await s.load();
        await s.bind(U, A);
        await s.setVerified(U, A, true);
        expect(s.get(U)?.verified).toBe(true);
        const nb = await s.bind(U, B);
        expect(nb.verified).toBe(false);
        expect(nb.previousFingerprints).toEqual([A]);
        expect(nb.changedAt).not.toBeNull();
        expect(await s.setVerified(U, A, true)).toBeNull(); // stale fingerprint cannot verify
    });
    test("unbind", async () => {
        const s = new BindingStore(join(dir, "b.json"));
        await s.load();
        await s.bind(U, A);
        expect(await s.unbind(U)).toBe(true);
        expect(await s.unbind(U)).toBe(false);
        expect(s.all()).toEqual([]);
    });
    test("corrupt and hostile files are sanitised", async () => {
        const path = join(dir, "b.json");
        await writeFile(path, JSON.stringify({
            version: 1,
            bindings: {
                [U]: { fingerprint: A, verified: "yes", addedAt: "x", previousFingerprints: ["junk", B] },
                "notasnowflake": { fingerprint: A, verified: true },
                "999999999999999999": { fingerprint: "short", verified: true },
            },
        }));
        const s = new BindingStore(path);
        await s.load();
        expect(s.all()).toHaveLength(1);
        expect(s.get(U)).toMatchObject({ fingerprint: A, verified: false, previousFingerprints: [B] });

        await writeFile(path, "{not json");
        const s2 = new BindingStore(path);
        await s2.load();
        expect(s2.all()).toEqual([]);
        const content = await readFile(path, "utf8").catch(() => null);
        expect(content).toBeNull(); // corrupt file moved aside, not silently overwritten
    });
});
