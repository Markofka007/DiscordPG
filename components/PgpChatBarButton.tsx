/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { ChatBarButton, ChatBarButtonFactory } from "@api/ChatButtons";
import { copyWithToast, getUniqueUsername } from "@utils/discord";
import { ContextMenuApi, Menu, showToast, UserStore } from "@webpack/common";

import { gpgBackend } from "../core/backend";
import { checkSendHook } from "../core/integrity";
import { FINGERPRINT_RE } from "../core/types";
import { settings } from "../settings";
import { getBinding, useBindings } from "../store/Bindings";
import { policyFor, setEncrypt, setSign, useChannelPrefsVersion } from "../store/ChannelPrefs";
import { lockNow } from "../store/lock";
import { openConversationSettings } from "./ConversationSettings";
import { BrokenLockIcon, LockIcon, SignatureIcon, UnlockIcon, WarningIcon } from "./icons";
import { openFingerprintModal, openGroupKeysModal, openKeyImportModal } from "./modals";
import { groupFpr } from "./verdict";

/** The lock in the message bar. Click: conversation settings. Right-click: quick toggles. */
export const PgpChatBarButton: ChatBarButtonFactory = ({ channel, isMainChat }) => {
    useBindings();
    useChannelPrefsVersion();
    const { ownKeyFingerprint } = settings.use(["ownKeyFingerprint"]);

    if (!isMainChat) return null;
    const policy = policyFor(channel.id);
    if (!policy) return null;
    const { conv, keys } = policy;
    const hook = checkSendHook();
    const hasOwnKey = FINGERPRINT_RE.test(ownKeyFingerprint);

    const recipientId = conv.recipientIds[0];
    const recipient = recipientId ? UserStore.getUser(recipientId) : null;
    const label = recipient ? getUniqueUsername(recipient) : recipientId;
    const binding = conv.kind === "dm" ? getBinding(recipientId) : null;
    const members = conv.recipientIds.length;
    const verified = keys.bound.filter(b => b.binding.verified).length;
    const settingsHint = " — click for settings";
    // "On" includes the blocked state, so the switch can always be used to turn encryption off again.
    const encryptOn = policy.encrypt || !!policy.sendBlocked;

    let Icon = UnlockIcon, cls = "vc-pg-chatbar-off", tooltip = "PGP: off" + settingsHint;
    if (hook === "broken") {
        Icon = WarningIcon; cls = "vc-pg-chatbar-warn";
        tooltip = "DiscordPG: Vencord's send hook is NOT installed. Messages cannot be encrypted or signed. Restart Discord / update Vencord.";
    } else if (!hasOwnKey) {
        Icon = BrokenLockIcon; cls = "vc-pg-chatbar-warn";
        tooltip = "DiscordPG: no own key selected. Open Settings → Plugins → DiscordPG.";
    } else if (policy.sendBlocked) {
        Icon = BrokenLockIcon; cls = "vc-pg-chatbar-warn";
        tooltip = `PGP encryption is ON but not possible: ${policy.sendBlocked}. Messages will NOT be sent until that is fixed or you turn encryption off${settingsHint}`;
    } else if (policy.encrypt) {
        Icon = LockIcon; cls = "vc-pg-chatbar-on";
        tooltip = conv.kind === "dm"
            ? `PGP encryption ON for ${label} (${binding!.verified ? "verified" : "unverified"} key ${groupFpr(binding!.fingerprint).slice(0, 24)}…)${policy.sign ? ", signed" : ", unsigned"}${settingsHint}`
            : `PGP encryption ON for ${members} ${conv.kind === "group" ? "members" : "recipients"} (${verified} verified)${policy.sign ? ", signed" : ", unsigned"}${settingsHint}`;
    } else if (policy.sign) {
        Icon = SignatureIcon; cls = "vc-pg-chatbar-sign";
        tooltip = `Signing messages without encryption (clearsigned)${settingsHint}`;
    } else if (policy.encryptBlocked) {
        Icon = UnlockIcon; cls = "vc-pg-chatbar-nokey";
        tooltip = `PGP: off (${policy.encryptBlocked})${settingsHint}`;
    }

    const onClick = () => {
        if (hook === "broken") return showToast({ text: "Encryption is unavailable: the send hook is missing.", variant: "critical" });
        openConversationSettings(channel.id);
    };

    const manageKeys = () => conv.kind === "dm" ? openKeyImportModal(recipientId, label) : openGroupKeysModal(conv.recipientIds);

    const onContextMenu = (e: React.MouseEvent) => {
        ContextMenuApi.openContextMenu(e, () => (
            <Menu.Menu navId="vc-pg-chatbar-menu" onClose={ContextMenuApi.closeContextMenu} aria-label="DiscordPG">
                <Menu.MenuCheckboxItem id="vc-pg-m-encrypt" label={policy.encryptBlocked ? `Encrypt messages (${policy.encryptBlocked})` : "Encrypt messages"} checked={encryptOn} disabled={!policy.sendBlocked && (!!policy.encryptBlocked || !hasOwnKey)} action={() => void setEncrypt(channel.id, !encryptOn)} />
                <Menu.MenuCheckboxItem id="vc-pg-m-sign" label="Sign messages" checked={policy.sign} disabled={!hasOwnKey} action={() => void setSign(channel.id, !policy.sign)} />
                <Menu.MenuSeparator />
                <Menu.MenuItem id="vc-pg-m-settings" label="Conversation settings…" action={() => openConversationSettings(channel.id)} />
                {conv.kind === "dm"
                    ? <>
                        <Menu.MenuItem id="vc-pg-fpr" label={binding ? "View / verify fingerprints" : "View my fingerprint"} action={() => openFingerprintModal(recipientId, label)} />
                        <Menu.MenuItem id="vc-pg-import" label={binding ? "Replace their key…" : "Import their key…"} action={() => openKeyImportModal(recipientId, label)} />
                    </>
                    : conv.kind === "group"
                        ? <Menu.MenuItem id="vc-pg-group" label={`Group keys (${keys.bound.length}/${members} bound)…`} action={manageKeys} />
                        : null}
                <Menu.MenuSeparator />
                <Menu.MenuItem id="vc-pg-share" label="Copy my public key" action={async () => {
                    if (!hasOwnKey) return showToast({ text: "No own key selected.", variant: "critical" });
                    const r = await gpgBackend.exportPublicKey(ownKeyFingerprint);
                    if (!r.ok) return showToast({ text: "Export failed.", variant: "critical" });
                    copyWithToast(r.armored, "Public key copied. Paste it to them, or use /pgp share.");
                }} />
                <Menu.MenuItem id="vc-pg-lock" label="Lock now (forget plaintext, drop PIN cache)" action={() => lockNow(true)} />
            </Menu.Menu>
        ));
    };

    return (
        <ChatBarButton tooltip={tooltip} onClick={onClick} onContextMenu={onContextMenu} buttonProps={{ "aria-label": tooltip }}>
            <Icon className={cls} />
        </ChatBarButton>
    );
};
