/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { Button } from "@components/Button";
import { Heading } from "@components/Heading";
import { Paragraph } from "@components/Paragraph";
import { copyWithToast, getUniqueUsername } from "@utils/discord";
import { ModalSize } from "@utils/modal";
import { RenderModalProps } from "@vencord/discord-types";
import { Modal, openModal, showToast, TextArea, useEffect, UserStore, useState } from "@webpack/common";

import { describeError, gpgBackend } from "../core/backend";
import { KeyInfo } from "../core/types";
import { canEncryptTo, isLargeAlgo } from "../native/colons";
import { settings } from "../settings";
import { bindKey, getBinding, unbindKey, useBindings, verifyKey } from "../store/Bindings";
import { groupFpr } from "./verdict";

function KeySummary({ info: k }: { info: KeyInfo }) {
    const problems: string[] = [];
    if (k.revoked) problems.push("REVOKED");
    if (k.expired) problems.push("expired");
    if (!canEncryptTo(k)) problems.push("has no usable encryption subkey");
    if (isLargeAlgo(k)) problems.push("RSA: encrypted messages will be large and may exceed Discord's character limit");
    return (
        <div className="vc-pg-section">
            <div className="vc-pg-fpr">{groupFpr(k.fingerprint)}</div>
            <Paragraph className="vc-pg-muted">
                {k.uids.map(u => u.uid).join(", ") || "(no user ID)"} · {k.algoName}{k.curve ? ` ${k.curve}` : k.bits ? ` ${k.bits}` : ""}
                {k.expires ? ` · expires ${new Date(k.expires * 1000).toLocaleDateString()}` : ""}
            </Paragraph>
            {problems.length > 0 && <Paragraph className="vc-pg-danger">{problems.join(" · ")}</Paragraph>}
        </div>
    );
}

export function KeyImportModal({ rootProps, userId, userLabel, initialArmored }: { rootProps: RenderModalProps; userId: string; userLabel: string; initialArmored?: string }) {
    const [armored, setArmored] = useState(initialArmored ?? "");
    const [keys, setKeys] = useState<KeyInfo[] | null>(null);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const existing = getBinding(userId);

    const doImport = async (text: string) => {
        setBusy(true); setError(null); setKeys(null);
        const r = await gpgBackend.importPublicKey(text);
        setBusy(false);
        if (!r.ok) { setError(describeError(r.error, r.detail)); return; }
        if (r.keys.length === 0) { setError("The key was imported but could not be listed back from gpg."); return; }
        setKeys(r.keys);
    };

    useEffect(() => { if (initialArmored) void doImport(initialArmored); }, []);

    const doBind = async (k: KeyInfo) => {
        setBusy(true);
        const r = await bindKey(userId, k.fingerprint, userLabel);
        setBusy(false);
        if (!r.ok) {
            if (r.error !== "cancelled") setError(describeError(r.error, r.detail));
            return;
        }
        showToast({ text: `Key bound to ${userLabel}. Compare fingerprints with them to mark it verified.`, variant: "success" });
        rootProps.onClose();
    };

    return (
        <Modal {...rootProps} title={`Import PGP key for ${userLabel}`} size={ModalSize.MEDIUM}>
            {existing && (
                <Paragraph className="vc-pg-warn vc-pg-section">
                    {userLabel} already has a bound key ({groupFpr(existing.fingerprint)}). Binding a different one will replace it and reset its verified status.
                </Paragraph>
            )}
            {!keys && (
                <div className="vc-pg-section">
                    <Paragraph className="vc-pg-muted">Paste their ASCII-armored public key block (<code>-----BEGIN PGP PUBLIC KEY BLOCK-----</code> … ). Only public keys are accepted.</Paragraph>
                    <TextArea className="vc-pg-textarea" value={armored} onChange={setArmored} placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----" />
                    <div className="vc-pg-row" style={{ marginTop: 8 }}>
                        <Button disabled={busy || !armored.trim()} onClick={() => doImport(armored)}>Import into keyring</Button>
                    </div>
                </div>
            )}
            {keys && (
                <div className="vc-pg-section">
                    <Heading tag="h4">Imported {keys.length === 1 ? "key" : `${keys.length} keys`}</Heading>
                    {keys.map(k => (
                        <div key={k.fingerprint}>
                            <KeySummary info={k} />
                            <div className="vc-pg-row">
                                <Button disabled={busy || !canEncryptTo(k)} onClick={() => doBind(k)}>Trust this key for {userLabel}</Button>
                                <Button variant="secondary" onClick={() => copyWithToast(k.fingerprint, "Fingerprint copied")}>Copy fingerprint</Button>
                            </div>
                        </div>
                    ))}
                    <Paragraph className="vc-pg-muted" style={{ marginTop: 8 }}>You will be asked to confirm in a system dialog. Afterwards, compare the fingerprint with {userLabel} over a channel you trust and mark it verified.</Paragraph>
                </div>
            )}
            {error && <Paragraph className="vc-pg-danger">{error}</Paragraph>}
        </Modal>
    );
}

export function openKeyImportModal(userId: string, userLabel: string, initialArmored?: string) {
    openModal(props => <KeyImportModal rootProps={props} userId={userId} userLabel={userLabel} initialArmored={initialArmored} />);
}

export function FingerprintModal({ rootProps, userId, userLabel }: { rootProps: RenderModalProps; userId: string; userLabel: string }) {
    useBindings();
    const binding = getBinding(userId);
    const own = settings.store.ownKeyFingerprint;
    const [busy, setBusy] = useState(false);

    const act = async (fn: () => Promise<{ ok: boolean; error?: string; detail?: string }>, okText: string) => {
        setBusy(true);
        const r = await fn();
        setBusy(false);
        if (!r.ok) { if (r.error !== "cancelled") showToast({ text: describeError(r.error as any, r.detail), variant: "critical" }); return; }
        showToast({ text: okText, variant: "success" });
    };

    return (
        <Modal {...rootProps} title={`PGP keys: you and ${userLabel}`} size={ModalSize.MEDIUM}>
            <div className="vc-pg-section">
                <Heading tag="h4">{userLabel}'s key {binding ? (binding.verified ? "· verified" : "· not yet verified") : ""}</Heading>
                {binding ? (
                    <>
                        <div className="vc-pg-fpr">{groupFpr(binding.fingerprint)}</div>
                        <Paragraph className="vc-pg-muted">
                            Bound {new Date(binding.addedAt).toLocaleString()}
                            {binding.changedAt ? ` · key changed ${new Date(binding.changedAt).toLocaleString()}` : ""}
                            {binding.previousFingerprints.length ? ` · ${binding.previousFingerprints.length} previous key(s)` : ""}
                        </Paragraph>
                    </>
                ) : <Paragraph className="vc-pg-muted">No key bound. Ask them to run <code>/pgp share</code> or paste their key via Import.</Paragraph>}
            </div>
            <div className="vc-pg-section">
                <Heading tag="h4">Your key</Heading>
                {own ? <div className="vc-pg-fpr">{groupFpr(own)}</div> : <Paragraph className="vc-pg-danger">No own key selected in DiscordPG settings.</Paragraph>}
            </div>
            <Paragraph className="vc-pg-muted vc-pg-section">
                Read the fingerprints to each other over a call or in person. If both match, mark the key verified. Never trust a fingerprint sent through Discord alone.
            </Paragraph>
            <div className="vc-pg-row">
                {binding && !binding.verified && (
                    <Button disabled={busy} onClick={() => act(() => verifyKey(userId, binding.fingerprint, userLabel), "Key marked as verified")}>Mark as verified</Button>
                )}
                {binding && <Button variant="secondary" onClick={() => copyWithToast(binding.fingerprint, "Fingerprint copied")}>Copy their fingerprint</Button>}
                {own && <Button variant="secondary" onClick={() => copyWithToast(own, "Fingerprint copied")}>Copy my fingerprint</Button>}
                <Button variant="secondary" onClick={() => { rootProps.onClose(); openKeyImportModal(userId, userLabel); }}>{binding ? "Replace key…" : "Import key…"}</Button>
                {binding && (
                    <Button variant="dangerSecondary" disabled={busy} onClick={() => act(async () => {
                        const r = await unbindKey(userId, binding.fingerprint, userLabel);
                        if (r.ok) rootProps.onClose();
                        return r;
                    }, "Key forgotten")}>Forget key</Button>
                )}
            </div>
        </Modal>
    );
}

export function openFingerprintModal(userId: string, userLabel: string) {
    openModal(props => <FingerprintModal rootProps={props} userId={userId} userLabel={userLabel} />);
}

/** Key status table for a set of users (group members or chosen recipients), with import / replace actions. */
export function MemberKeyTable({ memberIds }: { memberIds: string[] }) {
    useBindings();
    const rows = memberIds.map(id => {
        const user = UserStore.getUser(id);
        const label = user ? getUniqueUsername(user) : id;
        return { id, label, binding: getBinding(id) };
    });
    return (
        <table className="vc-pg-table">
                <thead><tr><th>Member</th><th>Key</th><th /></tr></thead>
                <tbody>
                    {rows.map(r => (
                        <tr key={r.id}>
                            <td>{r.label}</td>
                            <td>{r.binding
                                ? <><code>{groupFpr(r.binding.fingerprint).slice(0, 24)}…</code> <span className={r.binding.verified ? "vc-pg-verified" : "vc-pg-warn"}>{r.binding.verified ? "verified" : "unverified"}</span></>
                                : <span className="vc-pg-danger">none</span>}</td>
                            <td>
                                <div className="vc-pg-row">
                                    {r.binding && <Button size="small" variant="secondary" onClick={() => openFingerprintModal(r.id, r.label)}>Fingerprints</Button>}
                                    <Button size="small" variant={r.binding ? "secondary" : "primary"} onClick={() => openKeyImportModal(r.id, r.label)}>{r.binding ? "Replace…" : "Import…"}</Button>
                                </div>
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
    );
}

/** Group DM: every member's key status in one place. Encryption needs all of them bound (fail closed). */
export function GroupKeysModal({ rootProps, memberIds }: { rootProps: RenderModalProps; memberIds: string[] }) {
    useBindings();
    const bound = memberIds.filter(id => getBinding(id)).length;
    return (
        <Modal {...rootProps} title={`Group keys (${bound}/${memberIds.length} bound)`} size={ModalSize.MEDIUM}>
            <Paragraph className={bound === memberIds.length ? "vc-pg-verified" : "vc-pg-warn"}>
                {bound} of {memberIds.length} members have a bound PGP key. {bound === memberIds.length ? "Encryption can be turned on for this group." : "Every member needs a key before anything is encrypted; nothing is ever sent half-encrypted."}
            </Paragraph>
            <MemberKeyTable memberIds={memberIds} />
            <Paragraph className="vc-pg-muted" style={{ marginTop: 8 }}>Ask members to run <code>/pgp share</code> in this group; an "Import key" button then appears under their message.</Paragraph>
        </Modal>
    );
}

export function openGroupKeysModal(memberIds: string[]) {
    openModal(props => <GroupKeysModal rootProps={props} memberIds={memberIds} />);
}
