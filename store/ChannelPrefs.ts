/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Per-conversation choices: encrypt, sign, and (guild channels) the recipient list. Low
 * sensitivity: a hostile renderer flipping these cannot leak anything that was not already in the renderer,
 * and the main process only ever encrypts to bound or own keys. So plain DataStore is fine.
 */

import * as DataStore from "@api/DataStore";
import { Channel } from "@vencord/discord-types";
import { ChannelStore, useEffect, useState } from "@webpack/common";

import { Conversation, ConversationPrefs, describeConversation, Policy, policyFor as purePolicy } from "../core/conversation";
import { Snowflake } from "../core/types";
import { settings } from "../settings";
import { bindingsLoaded, getBinding } from "./Bindings";

const KEY = "DiscordPG.channelPrefs";
type Prefs = Record<string, ConversationPrefs>;

let prefs: Prefs = {};
const listeners = new Set<() => void>();

export async function loadChannelPrefs() {
    const stored = await DataStore.get<Prefs>(KEY);
    prefs = stored && typeof stored === "object" ? stored : {};
}

export const getPrefs = (channelId: string): ConversationPrefs => prefs[channelId] ?? {};
export function hasExplicitPref(channelId: string) { return channelId in prefs; }

export async function setPrefs(channelId: string, patch: Partial<ConversationPrefs>) {
    const next = { ...getPrefs(channelId), ...patch };
    for (const k of Object.keys(next) as (keyof ConversationPrefs)[]) if (next[k] === undefined) delete next[k];
    prefs = { ...prefs, [channelId]: next };
    listeners.forEach(fn => fn());
    await DataStore.set(KEY, prefs);
}

export const setEncrypt = (channelId: string, encrypt: boolean) => setPrefs(channelId, { encrypt });
export const setSign = (channelId: string, sign: boolean | undefined) => setPrefs(channelId, { sign });
/** Remember that a message went out encrypted here, which commits the conversation to encryption (see core policyFor). */
export function noteEncrypted(channelId: string) {
    if (!getPrefs(channelId).wasEncrypted) void setPrefs(channelId, { wasEncrypted: true }).catch(() => { /* in memory is enough for this session */ });
}
export const setRecipients = (channelId: string, recipients: Snowflake[]) => setPrefs(channelId, { recipients });

/** The conversation for a channel, with the user's chosen recipients filled in for guild channels. */
export function conversationFor(channel: Channel | null | undefined): Conversation | null {
    if (!channel) return null;
    return describeConversation(channel as any, getPrefs(channel.id).recipients);
}
export const conversationForId = (channelId: string) => conversationFor(ChannelStore.getChannel(channelId));

const policySettings = () => ({
    encryptByDefault: settings.store.encryptByDefault,
    signMessages: settings.store.signMessages,
});

/** The effective send policy for a channel, or null when DiscordPG does not apply there. */
export function policyFor(channelId: string): (Policy & { conv: Conversation }) | null {
    const conv = conversationForId(channelId);
    if (!conv) return null;
    return { ...purePolicy(conv, getPrefs(channelId), policySettings(), getBinding, bindingsLoaded()), conv };
}

/** Kept for callers that only care about the encrypt switch. */
export function isEncryptEnabled(channelId: string, _hasBinding?: boolean): boolean {
    return policyFor(channelId)?.encrypt ?? false;
}

export function useChannelPrefsVersion() {
    const [, bump] = useState(0);
    useEffect(() => {
        const fn = () => bump(n => n + 1);
        listeners.add(fn);
        return () => void listeners.delete(fn);
    }, []);
}
