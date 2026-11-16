/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/** The box behind the lock icon: encrypt / sign / recipients for one conversation. */

import { Button } from "@components/Button";
import { FormSwitch } from "@components/FormSwitch";
import { Heading } from "@components/Heading";
import { Paragraph } from "@components/Paragraph";
import { copyWithToast, getUniqueUsername } from "@utils/discord";
import { openModal } from "@utils/modal";
import { RenderModalProps } from "@vencord/discord-types";
import { ChannelStore, Checkbox, Modal, showToast, TextInput, UserStore, useState } from "@webpack/common";

import { gpgBackend } from "../core/backend";
import { checkSendHook } from "../core/integrity";
import { FINGERPRINT_RE, MAX_RECIPIENTS } from "../core/types";
import { settings } from "../settings";
import { getBinding, useBindings } from "../store/Bindings";
import { policyFor, setEncrypt, setRecipients, setSign, useChannelPrefsVersion } from "../store/ChannelPrefs";
import { lockNow } from "../store/lock";
import { MemberKeyTable, openFingerprintModal } from "./modals";
import { groupFpr } from "./verdict";

const userLabel = (id: string) => { const u = UserStore.getUser(id); return u ? getUniqueUsername(u) : id; };

function RecipientPicker({ channelId, chosen }: { channelId: string; chosen: string[] }) {
    const bindings = useBindings();
    const [query, setQuery] = useState("");
    const q = query.trim().toLowerCase();
    // Alphabetical and stable: toggling a recipient must not move the row under the cursor.
    const rows = bindings
        .map(b => ({ id: b.userId, label: userLabel(b.userId), verified: b.verified }))
        .filter(r => !q || r.label.toLowerCase().includes(q) || r.id.includes(q))
        .sort((a, b) => a.label.localeCompare(b.label));
    const max = MAX_RECIPIENTS - 1;
    const toggle = (id: string, on: boolean) => {
        const next = on ? [...chosen, id] : chosen.filter(x => x !== id);
        if (next.length > max) return showToast({ text: `At most ${max} recipients per message.`, variant: "critical" });
        void setRecipients(channelId, next);
    };
    return (
        <div className="vc-pg-section">
            <Heading tag="h4">Recipients ({chosen.length}/{max})</Heading>
            <Paragraph className="vc-pg-muted">Only people whose PGP key you have bound can be recipients. Bind keys from a user's context menu → DiscordPG → Import key.</Paragraph>
            {bindings.length > 6 && <TextInput value={query} onChange={setQuery} placeholder="Filter contacts…" />}
            <div className="vc-pg-picker">
                {rows.length === 0 && <Paragraph className="vc-pg-muted">{bindings.length ? "No contact matches." : "You have not bound any keys yet."}</Paragraph>}
                {rows.map(r => (
                    <Checkbox key={r.id} value={chosen.includes(r.id)} onChange={(_e, v) => toggle(r.id, v)} type="inverted">
                        <span>{r.label} <span className={r.verified ? "vc-pg-verified" : "vc-pg-warn"}>({r.verified ? "verified" : "unverified"})</span></span>
                    </Checkbox>
                ))}
            </div>
        </div>
    );
}

export function ConversationSettingsModal({ rootProps, channelId }: { rootProps: RenderModalProps; channelId: string }) {
    useBindings();
    useChannelPrefsVersion();
    const { ownKeyFingerprint, signMessages } = settings.use(["ownKeyFingerprint", "signMessages"]);
    const channel = ChannelStore.getChannel(channelId);
    const policy = policyFor(channelId);
    const hasOwnKey = FINGERPRINT_RE.test(ownKeyFingerprint);
    const hook = checkSendHook();

    if (!policy || !channel) {
        return <Modal {...rootProps} title="DiscordPG" size="sm"><Paragraph>DiscordPG does not work in this kind of channel.</Paragraph></Modal>;
    }
    const { conv } = policy;
    const title = conv.kind === "dm" ? `DiscordPG · ${userLabel(conv.recipientIds[0])}` : conv.kind === "group" ? "DiscordPG · this group" : `DiscordPG · #${channel.name}`;
    const verified = policy.keys.bound.filter(b => b.binding.verified).length;

    // Blocked-but-on is its own state: the conversation is committed to encryption, so nothing is sent (see core policyFor).
    const blockedHelp = policy.sendBlocked
        ? `On, but not possible right now: ${policy.sendBlocked}. Messages here will not be sent until that is fixed. Turn this off to send unencrypted.`
        : policy.encryptBlocked ? `Not possible right now: ${policy.encryptBlocked}.` : null;
    const encryptHelp = blockedHelp ?? (
        conv.kind === "guild"
            ? `Messages are encrypted to ${conv.recipientIds.length} chosen recipient${conv.recipientIds.length === 1 ? "" : "s"} (${verified} verified) and to you. Everyone else sees ciphertext.`
            : conv.kind === "dm"
                ? `Encrypted to ${userLabel(conv.recipientIds[0])}'s ${policy.keys.bound[0]?.binding.verified ? "verified" : "unverified"} key and to you.`
                : `Encrypted to all ${conv.recipientIds.length} members (${verified} verified) and to you.`
    );
    const signHelp = policy.signExplicit
        ? "Set for this conversation. "
        : policy.encrypt ? `Default for encrypted conversations (${signMessages ? "on" : "off"}; change it in the plugin settings). ` : "Default: off while encryption is off. ";

    return (
        <Modal {...rootProps} title={title} size="md">
            {hook === "broken" && <Paragraph className="vc-pg-danger vc-pg-section">Vencord's send hook is missing: nothing can be encrypted or signed until Discord is restarted / Vencord is updated.</Paragraph>}
            {!hasOwnKey && <Paragraph className="vc-pg-danger vc-pg-section">No own key selected. Open Settings → Plugins → DiscordPG and pick your key first.</Paragraph>}

            <FormSwitch
                title="Encrypt messages"
                description={encryptHelp}
                value={policy.encrypt || !!policy.sendBlocked}
                disabled={!policy.sendBlocked && (!!policy.encryptBlocked || !hasOwnKey)}
                onChange={v => void setEncrypt(channelId, v)}
            />
            {conv.kind === "guild" && <RecipientPicker channelId={channelId} chosen={conv.recipientIds} />}
            {conv.kind !== "dm" && conv.recipientIds.length > 0 && (
                <div className="vc-pg-section">
                    <Heading tag="h4">{conv.kind === "group" ? "Member keys" : "Recipient keys"}</Heading>
                    <MemberKeyTable memberIds={conv.recipientIds} />
                </div>
            )}

            <FormSwitch
                title="Sign messages"
                description={<>{signHelp}{policy.encrypt ? "Signatures ride inside the encrypted block." : "Without encryption the message is clearsigned: readable text with the signature underneath, which anyone can read and OpenPGP users can verify. The first time, a system dialog asks you to allow this for the session."}{policy.signExplicit && <> <button className="vc-pg-link" onClick={() => void setSign(channelId, undefined)}>Use default</button></>}</>}
                value={policy.sign}
                disabled={!hasOwnKey}
                onChange={v => void setSign(channelId, v)}
            />

            <div className="vc-pg-row" style={{ marginTop: 12 }}>
                {conv.kind === "dm" && <Button variant="secondary" onClick={() => openFingerprintModal(conv.recipientIds[0], userLabel(conv.recipientIds[0]))}>Fingerprints</Button>}
                <Button variant="secondary" disabled={!hasOwnKey} onClick={async () => {
                    const r = await gpgBackend.exportPublicKey(ownKeyFingerprint);
                    if (!r.ok) return showToast({ text: "Export failed.", variant: "critical" });
                    copyWithToast(r.armored, "Public key copied. Paste it to them, or use /pgp share.");
                }}>Copy my public key</Button>
                <Button variant="secondary" onClick={() => lockNow(true)}>Lock now</Button>
            </div>
            {hasOwnKey && <Paragraph className="vc-pg-muted" style={{ marginTop: 8 }}>Your key: <code>{groupFpr(ownKeyFingerprint)}</code></Paragraph>}
        </Modal>
    );
}

export function openConversationSettings(channelId: string) {
    openModal(props => <ConversationSettingsModal rootProps={props} channelId={channelId} />);
}
