/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { Button } from "@components/Button";
import ErrorBoundary from "@components/ErrorBoundary";
import { Heading } from "@components/Heading";
import { Paragraph } from "@components/Paragraph";
import { copyWithToast, getUniqueUsername } from "@utils/discord";
import { SearchableSelect, showToast, useEffect, UserStore, useState } from "@webpack/common";

import { BackendStatus, describeError, gpgBackend, KeyInfo } from "../core/backend";
import { checkSendHook } from "../core/integrity";
import { usesCard } from "../native/colons";
import { settings } from "../settings";
import { refreshBindings, unbindKey, useBindings, verifyKey } from "../store/Bindings";
import { lockNow } from "../store/lock";
import { openFingerprintModal } from "./modals";
import { groupFpr } from "./verdict";

const yes = (b: boolean | null | undefined) => b == null ? "unknown" : b ? "yes" : "no";

function Status({ status, keys }: { status: BackendStatus | null; keys: KeyInfo[] | null }) {
    const hook = checkSendHook();
    if (!status) return <Paragraph className="vc-pg-muted">Querying gpg…</Paragraph>;
    return (
        <table className="vc-pg-table">
            <tbody>
                <tr><th>gpg</th><td>{status.gpgPath ? `${status.gpgPath} (${status.gpgVersion ?? "?"}, libgcrypt ${status.libgcryptVersion ?? "?"})` : <span className="vc-pg-danger">not found{status.gpgReason ? ` — ${status.gpgReason}` : ""}</span>}</td></tr>
                <tr><th>gpg-agent reachable</th><td>{yes(status.agentReachable)}</td></tr>
                <tr><th>Smartcard present</th><td>{yes(status.cardPresent)}{status.cardSerial ? ` (serial ${status.cardSerial})` : ""}</td></tr>
                <tr><th>Secret keys</th><td>{keys ? keys.length : "…"}</td></tr>
                <tr><th>Send hook</th><td className={hook === "broken" ? "vc-pg-danger" : hook === "ok" ? "vc-pg-verified" : ""}>{hook === "unknown" ? "unknown until a chat is open" : hook}</td></tr>
                <tr><th>Bindings file</th><td><code>{status.bindingsPath}</code> ({status.bindingsCount} bound)</td></tr>
            </tbody>
        </table>
    );
}

function OwnKeyPicker({ keys }: { keys: KeyInfo[] | null }) {
    const { ownKeyFingerprint } = settings.use(["ownKeyFingerprint"]);
    if (!keys) return null;
    const usable = keys.filter(k => !k.revoked && !k.expired && [k, ...k.subkeys].some(p => p.capabilities.includes("e")));
    const options = usable.map(k => ({
        value: k.fingerprint,
        label: `${k.uids[0]?.uid ?? "(no uid)"} — ${groupFpr(k.fingerprint)}${usesCard(k, "e") ? " · on card" : ""}`,
    }));
    return (
        <div className="vc-pg-section">
            <Heading tag="h4">Your key</Heading>
            <Paragraph className="vc-pg-muted">Used to sign outgoing messages and as the second recipient so you can read your own sent messages. Needs an encryption-capable subkey.</Paragraph>
            {options.length === 0
                ? <Paragraph className="vc-pg-danger">No usable secret key found in your GnuPG keyring.</Paragraph>
                : (
                    <SearchableSelect
                        options={options}
                        value={options.find(o => o.value === ownKeyFingerprint)?.value}
                        placeholder="Select your key"
                        maxVisibleItems={6}
                        closeOnSelect={true}
                        onChange={(v: string) => { settings.store.ownKeyFingerprint = v; }}
                    />
                )}
            {ownKeyFingerprint && !options.some(o => o.value === ownKeyFingerprint) && (
                <Paragraph className="vc-pg-danger">The configured key {groupFpr(ownKeyFingerprint)} is not (or no longer) a usable secret key in this keyring.</Paragraph>
            )}
        </div>
    );
}

function BindingsTable() {
    const bindings = useBindings();
    if (bindings.length === 0) return <Paragraph className="vc-pg-muted">No keys bound yet. Open a DM and click the lock, or ask a contact to run <code>/pgp share</code>.</Paragraph>;
    return (
        <table className="vc-pg-table">
            <thead><tr><th>User</th><th>Fingerprint</th><th>Verified</th><th /></tr></thead>
            <tbody>
                {bindings.map(b => {
                    const user = UserStore.getUser(b.userId);
                    const label = user ? getUniqueUsername(user) : b.userId;
                    return (
                        <tr key={b.userId}>
                            <td>{label}<br /><span className="vc-pg-muted">{b.userId}</span></td>
                            <td><code>{groupFpr(b.fingerprint)}</code>{b.changedAt && <><br /><span className="vc-pg-warn">key changed {new Date(b.changedAt).toLocaleDateString()}</span></>}</td>
                            <td className={b.verified ? "vc-pg-verified" : "vc-pg-warn"}>{b.verified ? "yes" : "no"}</td>
                            <td>
                                <div className="vc-pg-row">
                                    <Button size="small" variant="secondary" onClick={() => openFingerprintModal(b.userId, label)}>Details</Button>
                                    {!b.verified && <Button size="small" onClick={() => verifyKey(b.userId, b.fingerprint, label)}>Verify</Button>}
                                    <Button size="small" variant="dangerSecondary" onClick={() => unbindKey(b.userId, b.fingerprint, label)}>Forget</Button>
                                </div>
                            </td>
                        </tr>
                    );
                })}
            </tbody>
        </table>
    );
}

function Panel() {
    const [status, setStatus] = useState<BackendStatus | null>(null);
    const [keys, setKeys] = useState<KeyInfo[] | null>(null);
    const { ownKeyFingerprint } = settings.use(["ownKeyFingerprint"]);

    const refresh = async () => {
        setStatus(null); setKeys(null);
        const [s, k] = await Promise.all([gpgBackend.status(), gpgBackend.listSecretKeys()]);
        setStatus(s);
        setKeys(k.ok ? k.keys : []);
        if (!k.ok) showToast({ text: describeError(k.error, k.detail), variant: "critical" });
        await refreshBindings();
    };
    useEffect(() => { void refresh(); }, []);

    return (
        <div>
            <div className="vc-pg-section">
                <Heading tag="h4">GnuPG status</Heading>
                <Status status={status} keys={keys} />
                <div className="vc-pg-row" style={{ marginTop: 8 }}>
                    <Button size="small" variant="secondary" onClick={refresh}>Refresh</Button>
                    <Button size="small" variant="secondary" disabled={!ownKeyFingerprint} onClick={async () => {
                        const r = await gpgBackend.exportPublicKey(ownKeyFingerprint);
                        if (!r.ok) return showToast({ text: describeError(r.error, r.detail), variant: "critical" });
                        copyWithToast(r.armored, "Your public key was copied");
                    }}>Copy my public key</Button>
                    <Button size="small" variant="dangerSecondary" onClick={() => lockNow(true)}>Lock now</Button>
                </div>
            </div>
            <OwnKeyPicker keys={keys} />
            <div className="vc-pg-section">
                <Heading tag="h4">Bound contact keys</Heading>
                <Paragraph className="vc-pg-muted">Stored by the main process in a file only your user can read. Changes always ask for confirmation in a system dialog.</Paragraph>
                <BindingsTable />
            </div>
            <Paragraph className="vc-pg-muted">
                YubiKey tip: <code>ykman openpgp keys set-touch dec cached</code> requires a touch per decryption but lets a burst of messages decrypt within one 15 s window.
            </Paragraph>
        </div>
    );
}

export const SettingsPanel = ErrorBoundary.wrap(Panel);
