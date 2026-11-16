/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/** Idle auto-lock: forget plaintext and ask gpg-agent to drop cached PINs. */

import { showToast } from "@webpack/common";

import { gpgBackend } from "../core/backend";
import { settings } from "../settings";
import { clearAll, setActivityHook, size } from "./DecryptStore";

let timer: ReturnType<typeof setTimeout> | null = null;

export async function lockNow(announce = false) {
    const had = size();
    clearAll();
    await gpgBackend.lock();
    if (announce || had > 0) showToast({ text: "DiscordPG locked: decrypted text forgotten, PIN cache cleared.", variant: "message" as any });
}

export function noteActivity() {
    if (timer) clearTimeout(timer);
    timer = null;
    const minutes = Number(settings.store.autoLockMinutes) || 0;
    if (minutes <= 0) return;
    timer = setTimeout(() => { timer = null; void lockNow(); }, minutes * 60_000);
}

export function startAutoLock() {
    setActivityHook(noteActivity);
    noteActivity();
}

export function stopAutoLock() {
    setActivityHook(null);
    if (timer) clearTimeout(timer);
    timer = null;
}
