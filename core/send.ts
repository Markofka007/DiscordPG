/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/** The outgoing path. Everything here fails closed: on any doubt the message is not sent. */

import { MessageEditListener, MessageSendListener } from "@api/MessageEvents";
import { getUniqueUsername } from "@utils/discord";
import { Logger } from "@utils/Logger";
import { CloudUpload } from "@vencord/discord-types";
import { showToast, UserStore } from "@webpack/common";

import { confirmUnencryptedFiles } from "../components/alerts";
import { settings } from "../settings";
import { bindingsLoaded, getBinding, refreshBindings } from "../store/Bindings";
import { conversationForId, noteEncrypted, policyFor } from "../store/ChannelPrefs";
import { getRecord, rememberOutgoing } from "../store/DecryptStore";
import { noteActivity } from "../store/lock";
import { describeError, gpgBackend } from "./backend";
import { memberKeys, recipientFingerprints } from "./conversation";
import { FINGERPRINT_RE, MAX_RECIPIENTS, SIGN_TEXT_MAX_CHARS } from "./types";
import { draftUploads, encryptUploads, releaseUploads, restoreUpload, restoreUploads, uploadsBlocker, wantsEncryption } from "./uploads";
import { discordContentLimit, extractArmor, extractDetachedSigned, wrapForDiscord } from "./wire";

const logger = new Logger("DiscordPG");

const cancel = (reason: string): { cancel: true } => {
    showToast({ text: `Not sent — ${reason}`, variant: "critical", duration: 8000 });
    return { cancel: true };
};

export const userName = (userId: string) => {
    const u = UserStore.getUser(userId);
    return u ? getUniqueUsername(u) : userId;
};

/** Who an outgoing message in this channel must be encrypted to, or why it cannot be. */
export function planRecipients(channelId: string): { ok: true; fingerprints: string[]; own: string } | { ok: false; reason: string } {
    const conv = conversationForId(channelId);
    if (!conv) return { ok: false, reason: "DiscordPG does not work in this kind of channel" };
    if (conv.kind === "guild" && conv.recipientIds.length === 0) return { ok: false, reason: "no recipients are chosen for this channel (click the lock icon)" };
    const keys = memberKeys(conv.recipientIds, getBinding);
    if (!keys.complete) {
        const names = keys.unbound.map(userName);
        return {
            ok: false,
            reason: conv.kind === "dm"
                ? "no PGP key is bound to this user"
                : `no PGP key is bound to ${names.length} ${conv.kind === "group" ? "member" : "recipient"}${names.length === 1 ? "" : "s"}: ${names.join(", ")}`,
        };
    }
    const own = settings.store.ownKeyFingerprint;
    if (!FINGERPRINT_RE.test(own)) return { ok: false, reason: "no own key selected in DiscordPG settings" };
    const fingerprints = recipientFingerprints(keys, own);
    if (fingerprints.length > MAX_RECIPIENTS) return { ok: false, reason: `too many recipients (${fingerprints.length})` };
    return { ok: true, fingerprints, own };
}

const contentLimit = () => discordContentLimit(UserStore.getCurrentUser()?.premiumType);

async function encryptFor(channelId: string, plaintext: string, sign: boolean): Promise<{ wire: string } | { cancel: true }> {
    const plan = planRecipients(channelId);
    if (!plan.ok) return cancel(plan.reason);

    const res = await gpgBackend.encryptAndSign({
        plaintext,
        recipients: plan.fingerprints,
        signWith: sign ? plan.own : null,
    });
    if (!res.ok) return cancel(describeError(res.error, res.detail));

    const wire = wrapForDiscord(res.armored, settings.store.wrapInCodeBlock);
    const limit = contentLimit();
    if (wire.length > limit) return cancel(`the encrypted message is ${wire.length} characters, over Discord's limit of ${limit} (plaintext: ${plaintext.length}, recipients: ${plan.fingerprints.length}). Shorten it.`);

    rememberOutgoing(res.armored, plaintext, plan.own, "encrypted");
    noteEncrypted(channelId);
    noteActivity();
    return { wire };
}

/**
 * Sign without encrypting: the content is replaced by a clearsigned block (readable text, signature underneath).
 * Incoming messages in the older encoded / detached forms are still verified, but we no longer produce them.
 */
async function signOnly(channelId: string, text: string): Promise<{ wire: string } | { cancel: true }> {
    const own = settings.store.ownKeyFingerprint;
    if (!FINGERPRINT_RE.test(own)) return cancel("signing is on but no own key is selected in DiscordPG settings");
    const trimmed = text.trim();
    if (trimmed.length > SIGN_TEXT_MAX_CHARS) return cancel(`messages longer than ${SIGN_TEXT_MAX_CHARS} characters cannot be signed`);

    const res = await gpgBackend.sign({ text: trimmed, channelId, signWith: own });
    if (!res.ok) return cancel(res.error === "cancelled" ? "you declined signing for this session (turn 'Sign messages' off to send unsigned)" : describeError(res.error, res.detail));
    noteActivity();

    const wire = wrapForDiscord(res.armored, settings.store.wrapInCodeBlock);
    const limit = contentLimit();
    if (wire.length > limit) return cancel(`the signed message is ${wire.length} characters, over Discord's limit of ${limit}. Shorten it.`);
    rememberOutgoing(res.armored, trimmed, own, "signed");
    return { wire };
}

/** Effective per-channel switch (see core/conversation.ts policyFor). */
export function encryptionOn(channelId: string): boolean {
    return policyFor(channelId)?.encrypt ?? false;
}

/**
 * Attachments in the composer: encrypt the locked ones in place (fail closed), and if the text is going out
 * encrypted next to unlocked files, make the user confirm that once.
 */
async function handleUploads(channelId: string, uploads: CloudUpload[], textEncrypted: boolean): Promise<{ cancel: true } | null> {
    // Fail closed if Discord already uploaded a file we were supposed to encrypt (see core/uploadPolicy.ts).
    const blocker = uploadsBlocker(uploads);
    if (blocker) return cancel(blocker);
    const locked = uploads.filter(wantsEncryption);
    const clear = uploads.filter(u => !wantsEncryption(u));
    clear.forEach(restoreUpload); // toggled off again after an earlier, failed attempt

    if (textEncrypted && clear.length && settings.store.warnUnencryptedAttachments) {
        if (!(await confirmUnencryptedFiles(clear.map(u => u.filename)))) return { cancel: true };
    }
    if (!locked.length) return null;

    const plan = planRecipients(channelId);
    if (!plan.ok) { restoreUploads(uploads); return cancel(`${locked.length === 1 ? "an attachment is" : "attachments are"} locked but ${plan.reason}`); }
    const res = await encryptUploads(uploads, { recipients: plan.fingerprints, signWith: settings.store.signMessages ? plan.own : null });
    if (!res.ok) return cancel(res.reason);
    noteActivity();
    return null;
}

export const onBeforeMessageSend: MessageSendListener = async (channelId, msg) => {
    try {
        const uploads = draftUploads(channelId);
        // Never judge a send against an empty binding cache: a message racing startup, or following a failed
        // load, would look like "nobody has a key" and go out in plaintext. Load on demand; if that fails too,
        // the policy below blocks every conversation that wants encryption.
        if (!bindingsLoaded()) await refreshBindings();
        const policy = policyFor(channelId);
        if (!policy) { releaseUploads(uploads); return; }
        const content = msg.content ?? "";
        // Already PGP (e.g. the output of /pgp share) - never double-wrap.
        const hasText = !!content.trim() && !extractArmor(content);
        // No silent downgrade (see core/conversation.ts policyFor): encryption is on here but impossible right now.
        if (hasText && policy.sendBlocked) {
            return cancel(`encryption is on for this conversation, but ${policy.sendBlocked}. Fix that, or turn encryption off (lock icon in the message bar) to send unencrypted.`);
        }
        const textEncrypted = hasText && policy.encrypt;

        if (uploads.length) {
            const u = await handleUploads(channelId, uploads, textEncrypted);
            if (u) return u;
        }
        if (hasText) {
            if (policy.encrypt) {
                const r = await encryptFor(channelId, content, policy.sign);
                if ("cancel" in r) { restoreUploads(uploads); return r; }
                msg.content = r.wire;
            } else if (policy.sign) {
                const r = await signOnly(channelId, content);
                if ("cancel" in r) { restoreUploads(uploads); return r; }
                msg.content = r.wire;
            }
        }
        // Everything is in its final form: let Discord's send queue upload the (now encrypted) files.
        releaseUploads(uploads);
    } catch (e) {
        logger.error("pre-send failed", e);
        return cancel("internal error while encrypting");
    }
};

export const onBeforeMessageEdit: MessageEditListener = async (channelId, messageId, msg) => {
    try {
        const record = getRecord(messageId);
        if (!record) return; // was never one of ours
        let content = msg.content ?? "";
        if (!content.trim() || extractArmor(content)) return;
        // Editing an old detached-signed message: the signature block is still in the edit box; drop it and re-sign the text.
        content = extractDetachedSigned(content)?.text ?? content;
        const policy = policyFor(channelId);
        if (!policy) return cancel("DiscordPG no longer applies to this channel");
        const wasEncrypted = record.entry.state === "ok" ? record.entry.mode === "encrypted" : true;
        // Re-protect at least as strongly as the original: an encrypted message must stay encrypted.
        const r = wasEncrypted || policy.encrypt || policy.sendBlocked
            ? await encryptFor(channelId, content, policy.sign || wasEncrypted && settings.store.signMessages)
            : await signOnly(channelId, content);
        if ("cancel" in r) return r;
        msg.content = r.wire;
    } catch (e) {
        logger.error("pre-edit failed", e);
        return cancel("internal error while encrypting");
    }
};
