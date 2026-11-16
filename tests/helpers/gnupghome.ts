import { execFile } from "child_process";
import { mkdtemp, rm, writeFile } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { promisify } from "util";

import { findGpg } from "../../native/gpg";

const execFileP = promisify(execFile);

export const LOOPBACK = ["--pinentry-mode", "loopback", "--passphrase", ""];

export interface TestHome {
    dir: string;
    gpg: string;
    run(args: string[], input?: string): Promise<{ stdout: string; stderr: string }>;
    genKey(uid: string, passphrase?: string): Promise<string>;
    cleanup(): Promise<void>;
}

/**
 * Throwaway GNUPGHOME with its own agent. Never touches the user's keyring.
 * `keyboxd: true` selects the keyboxd (SQLite) keyring backend that GnuPG 2.4 uses for new installations;
 * the default here is the classic pubring.kbx. Key lookup differs between the two, so tests that depend on
 * lookup order run against both. Older gpg versions ignore the option.
 */
export async function makeHome(opts: { keyboxd?: boolean } = {}): Promise<TestHome> {
    const { path: gpg } = await findGpg(null);
    if (!gpg) throw new Error("gpg not found; integration tests need GnuPG installed");
    const dir = await mkdtemp(join(tmpdir(), "discordpg-test-"));
    if (opts.keyboxd) await writeFile(join(dir, "common.conf"), "use-keyboxd\n", { mode: 0o600 });

    const run = async (args: string[], input?: string) => {
        const child = execFileP(gpg, ["--homedir", dir, "--batch", "--no-tty", ...args], { maxBuffer: 8 * 1024 * 1024 });
        if (input != null) child.child.stdin!.end(input);
        try {
            return await child;
        } catch (e: any) {
            return { stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
        }
    };

    const genKey = async (uid: string, passphrase = "") => {
        const pp = ["--pinentry-mode", "loopback", "--passphrase", passphrase];
        await run([...pp, "--quick-gen-key", uid, "ed25519", "cert", "never"]);
        const { stdout } = await run(["--with-colons", "--list-keys", uid]);
        const fpr = /^fpr:+([0-9A-F]{40}):/m.exec(stdout)?.[1];
        if (!fpr) throw new Error("key generation failed: " + stdout);
        await run([...pp, "--quick-add-key", fpr, "cv25519", "encr", "never"]);
        await run([...pp, "--quick-add-key", fpr, "ed25519", "sign", "never"]);
        return fpr;
    };

    const cleanup = async () => {
        await execFileP("gpgconf", ["--homedir", dir, "--kill", "all"]).catch(() => { });
        await rm(dir, { recursive: true, force: true });
    };

    return { dir, gpg, run, genKey, cleanup };
}
