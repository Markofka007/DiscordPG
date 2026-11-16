/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Hook-integrity check.
 *
 * Our pre-send / pre-edit listeners only run if Vencord's MessageEventsAPI
 * patches applied to Discord's composer and edit-box modules. If a Discord
 * update broke one of those patches, every "encrypted" conversation would
 * silently go out in plaintext, so we refuse to pretend encryption is on
 * unless we have proof the hook is in place.
 *
 * Production Vencord builds keep no inspectable record of applied patches
 * (patched factories are run once and discarded; `toString` returns the
 * original source). So the proof is a *witness patch*: DiscordPG registers
 * its own patch on the same modules, after MessageEventsAPI's (userplugins
 * are registered last), whose match only succeeds if the injected
 * `_handlePreSend` / `_handlePreEdit` call is present in the patched code.
 * The replacement function records that fact and leaves the code untouched.
 */

import { search, wreq } from "@webpack";

export type HookStatus = "ok" | "broken" | "unknown";
export type HookKind = "send" | "edit";

/** `find` strings of the modules MessageEventsAPI patches; must stay identical to Vencord's. */
export const HOOK_FINDS: Record<HookKind, string> = {
    send: ".handleSendMessage,onResize:",
    edit: "#{intl::EDIT_TEXTAREA_HELP}",
};

/** What MessageEventsAPI injects; our witness patches match on exactly this. */
export const HOOK_MARKERS: Record<HookKind, RegExp> = {
    send: /Vencord\.Api\.MessageEvents\._handlePreSend\(/,
    edit: /Vencord\.Api\.MessageEvents\._handlePreEdit\(/,
};

const witnessed: Record<HookKind, boolean> = { send: false, edit: false };
const lastBroken: Record<HookKind, number> = { send: 0, edit: 0 };
const BROKEN_TTL_MS = 30_000;

/** Called from the witness patches' replace functions, i.e. at patch time. */
export function witnessHook(kind: HookKind) {
    witnessed[kind] = true;
}

export function checkHook(kind: HookKind): HookStatus {
    if (witnessed[kind]) return "ok";
    const now = Date.now();
    if (now - lastBroken[kind] < BROKEN_TTL_MS) return "broken";

    try {
        // Factories are keyed by module id; wreq.c holds the modules that have actually run.
        const ids = Object.keys(search(HOOK_FINDS[kind]));
        if (ids.length === 0) return "unknown";          // chunk not loaded yet
        const cache = wreq?.c;
        const ran = !!cache && ids.some(id => cache[id] != null);
        if (!ran) return "unknown";                        // defined but never executed, so not patched yet
        lastBroken[kind] = now;
        return "broken";                                   // module ran without our witness firing
    } catch {
        return "unknown";
    }
}

export const checkSendHook = () => checkHook("send");
export const checkEditHook = () => checkHook("edit");

/** Test hook only. */
export function _resetHookWitness() {
    witnessed.send = witnessed.edit = false;
    lastBroken.send = lastBroken.edit = 0;
}
