/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/** Renderer-side read cache of the main-process binding store. Mutations go through bindingsApi and then refresh(). */

import { Logger } from "@utils/Logger";
import { useEffect, useState } from "@webpack/common";

import { bindingsApi } from "../core/backend";
import { Binding, Fingerprint, Snowflake } from "../core/types";

const logger = new Logger("DiscordPG");
let cache = new Map<Snowflake, Binding>();
let loaded = false;
const listeners = new Set<() => void>();

export async function refreshBindings(): Promise<void> {
    const r = await bindingsApi.getAll();
    if (!r.ok) { logger.warn("could not load bindings", r.error, r.detail); return; }
    cache = new Map(r.bindings.map(b => [b.userId, b]));
    loaded = true;
    listeners.forEach(fn => fn());
}

export const bindingsLoaded = () => loaded;
export const getBinding = (userId: Snowflake): Binding | null => cache.get(userId) ?? null;
export const allBindings = (): Binding[] => [...cache.values()];

export function useBindings(): Binding[] {
    const [, bump] = useState(0);
    useEffect(() => {
        const fn = () => bump(n => n + 1);
        listeners.add(fn);
        return () => void listeners.delete(fn);
    }, []);
    return allBindings();
}

export async function bindKey(userId: Snowflake, fingerprint: Fingerprint, userLabel: string) {
    const r = await bindingsApi.bind(userId, fingerprint, userLabel);
    if (r.ok) await refreshBindings();
    return r;
}

export async function verifyKey(userId: Snowflake, fingerprint: Fingerprint, userLabel: string) {
    const r = await bindingsApi.verify(userId, fingerprint, userLabel);
    if (r.ok) await refreshBindings();
    return r;
}

export async function unbindKey(userId: Snowflake, fingerprint: Fingerprint, userLabel: string) {
    const r = await bindingsApi.unbind(userId, fingerprint, userLabel);
    if (r.ok) await refreshBindings();
    return r;
}
