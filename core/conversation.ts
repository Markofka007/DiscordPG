/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Which conversations DiscordPG encrypts and who the recipients are. Pure TS
 * (structurally typed on the few Channel fields we read) so it is unit-testable.
 */

import { Binding, Fingerprint, Snowflake } from "./types";

export const CHANNEL_DM = 1;
export const CHANNEL_GROUP_DM = 3;
/** Guild text-like channels: text, announcement, announcement thread, public thread, private thread. */
export const GUILD_TEXT_TYPES: readonly number[] = [0, 5, 10, 11, 12];

export interface ConversationChannel {
    id: string;
    type: number;
    /** Other members' user IDs (never includes the current user). DMs and group DMs. */
    recipients?: string[];
}

export interface Conversation {
    kind: "dm" | "group" | "guild";
    channelId: string;
    /** Everyone except us. Non-empty for DMs/groups; for guild channels the user's chosen recipients (may be empty). */
    recipientIds: Snowflake[];
}

const cleanIds = (ids: readonly unknown[] | undefined) => [...new Set((ids ?? []).filter((id): id is string => typeof id === "string" && id.length > 0))];

/**
 * DMs and group DMs carry their recipients; guild text channels use the recipient list the user picked for
 * that channel (`guildRecipients`). null for anything else (voice, forum containers, empty groups).
 */
export function describeConversation(channel: ConversationChannel | null | undefined, guildRecipients?: readonly Snowflake[]): Conversation | null {
    if (!channel) return null;
    if (channel.type === CHANNEL_DM) {
        const ids = cleanIds(channel.recipients);
        return ids.length === 1 ? { kind: "dm", channelId: channel.id, recipientIds: ids } : null;
    }
    if (channel.type === CHANNEL_GROUP_DM) {
        const ids = cleanIds(channel.recipients);
        return ids.length >= 1 ? { kind: "group", channelId: channel.id, recipientIds: ids } : null;
    }
    if (GUILD_TEXT_TYPES.includes(channel.type)) {
        return { kind: "guild", channelId: channel.id, recipientIds: cleanIds(guildRecipients) };
    }
    return null;
}

export interface MemberKeys {
    bound: Array<{ userId: Snowflake; binding: Binding }>;
    /** Members with no key bound. Encryption is impossible while this is non-empty (fail closed). */
    unbound: Snowflake[];
    /** True when every member has a bound key. */
    complete: boolean;
}

export function memberKeys(recipientIds: Snowflake[], getBinding: (userId: Snowflake) => Binding | null): MemberKeys {
    const bound: MemberKeys["bound"] = [];
    const unbound: Snowflake[] = [];
    for (const userId of recipientIds) {
        const binding = getBinding(userId);
        if (binding) bound.push({ userId, binding });
        else unbound.push(userId);
    }
    return { bound, unbound, complete: unbound.length === 0 };
}

/** Recipient fingerprints for an outgoing message: every member's key plus our own, de-duplicated, order preserved. */
export function recipientFingerprints(keys: MemberKeys, own: Fingerprint): Fingerprint[] {
    const out: Fingerprint[] = [];
    for (const { binding } of keys.bound) if (!out.includes(binding.fingerprint)) out.push(binding.fingerprint);
    if (!out.includes(own)) out.push(own);
    return out;
}

/** The user's per-conversation choices (renderer DataStore). All optional: absent means "use the default policy". */
export interface ConversationPrefs {
    encrypt?: boolean;
    sign?: boolean;
    /**
     * Set once a message has gone out encrypted here. From then on the conversation is committed to
     * encryption: if it stops being possible, sending is refused instead of falling back to plaintext.
     */
    wasEncrypted?: boolean;
    /** Guild channels only: who to encrypt to. */
    recipients?: Snowflake[];
}

export interface PolicySettings {
    encryptByDefault: boolean;
    signMessages: boolean;
}

export interface Policy {
    /** Outgoing text is encrypted (wanted AND possible). */
    encrypt: boolean;
    /** Why encryption is impossible right now (even if wanted), or null. */
    encryptBlocked: string | null;
    /** The user wants encryption (explicit preference, or the default policy). */
    encryptWanted: boolean;
    /**
     * Non-null when outgoing text must be REFUSED rather than sent unencrypted: encryption is wanted, is not
     * possible right now, and this conversation is committed to it (see policyFor). The value is the reason.
     */
    sendBlocked: string | null;
    sign: boolean;
    /** Was `sign` set explicitly, or derived from `encrypt`? Informational for the UI. */
    signExplicit: boolean;
    keys: MemberKeys;
}

/**
 * What happens to an outgoing message in this conversation. Pure, so the rules are testable:
 * - DMs/groups encrypt when wanted (pref, else encryptByDefault) and every member has a key.
 * - Guild channels encrypt only on explicit opt-in with at least one still-bound recipient.
 * - Signing defaults to the global setting when encrypting, and to OFF when not encrypting.
 * - No silent downgrade: when encryption is wanted but not possible, text is only allowed out unencrypted in a
 *   conversation that was never encrypted and never explicitly switched on (the ordinary DM with someone who
 *   has no key). If the user turned encryption on, or a message already went out encrypted, or we do not even
 *   know the bindings (`bindingsKnown` false: not loaded yet, or loading failed), sending is blocked until the
 *   cause is fixed or the user turns encryption off. Otherwise a member added to a group DM, a lost binding or
 *   a failed load would quietly turn the next message into plaintext.
 */
export function policyFor(conv: Conversation, prefs: ConversationPrefs, settings: PolicySettings, getBinding: (id: Snowflake) => Binding | null, bindingsKnown = true): Policy {
    const keys = memberKeys(conv.recipientIds, getBinding);
    let encryptWanted: boolean;
    let encryptBlocked: string | null = null;
    if (conv.kind === "guild") {
        encryptWanted = prefs.encrypt === true;
        if (conv.recipientIds.length === 0) encryptBlocked = "no recipients chosen for this channel";
        else if (!keys.complete) encryptBlocked = `${keys.unbound.length} chosen recipient${keys.unbound.length === 1 ? " has" : "s have"} no key bound any more`;
    } else {
        encryptWanted = prefs.encrypt ?? settings.encryptByDefault;
        if (!keys.complete) encryptBlocked = conv.kind === "dm" ? "no PGP key is bound to this user" : `${keys.unbound.length} member${keys.unbound.length === 1 ? " has" : "s have"} no PGP key`;
    }
    if (!bindingsKnown && conv.recipientIds.length > 0) encryptBlocked = "DiscordPG could not load your key bindings";
    const encrypt = encryptWanted && encryptBlocked === null;
    const committed = prefs.encrypt === true || prefs.wasEncrypted === true;
    const sendBlocked = encryptWanted && encryptBlocked !== null && (committed || !bindingsKnown) ? encryptBlocked : null;
    const signExplicit = typeof prefs.sign === "boolean";
    const sign = signExplicit ? prefs.sign! : (encrypt ? settings.signMessages : false);
    return { encrypt, encryptBlocked, encryptWanted, sendBlocked, sign, signExplicit, keys };
}
