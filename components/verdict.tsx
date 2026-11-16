/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { IconComponent } from "@utils/types";

import { SigVerdict } from "../core/types";
import { BrokenLockIcon, LockIcon, WarningIcon } from "./icons";

export const groupFpr = (f: string) => f.replace(/(.{4})/g, "$1 ").trim();

export interface VerdictView {
    /** short label for footers/tooltips */
    label: string;
    /** longer explanation */
    detail: string;
    tone: "verified" | "self" | "unverified" | "warn" | "danger";
    Icon: IconComponent;
    /** should requireSignatures hide the content behind a click? */
    guard: boolean;
}

export interface VerdictContext {
    /** The signature names a different Discord channel than the one the message is in. */
    channelMismatch?: boolean;
    mode?: "encrypted" | "signed";
}

export function describeVerdict(v: SigVerdict, authorName: string, ctx: VerdictContext = {}): VerdictView {
    const base = describeBaseVerdict(v, authorName);
    if (ctx.channelMismatch && !base.guard) {
        return {
            label: `${base.label}, but for a DIFFERENT channel`,
            detail: `${base.detail} However, the signature says it was made for another Discord channel, so this text was probably copied here from somewhere else.`,
            tone: "danger", Icon: WarningIcon, guard: true,
        };
    }
    return base;
}

function describeBaseVerdict(v: SigVerdict, authorName: string): VerdictView {
    switch (v.kind) {
        case "self":
            return { label: "signed by you", detail: `Signed with your key ${groupFpr(v.fingerprint)}.`, tone: "self", Icon: LockIcon, guard: false };
        case "verified":
            return { label: `signed by ${authorName} (verified)`, detail: `Signed by ${authorName}'s verified key ${groupFpr(v.fingerprint)}.`, tone: "verified", Icon: LockIcon, guard: false };
        case "unverified-contact":
            return { label: `signed by ${authorName} (key not yet verified)`, detail: `Signed by the key you bound to ${authorName}, ${groupFpr(v.fingerprint)}, but you have not confirmed that fingerprint with them yet.`, tone: "unverified", Icon: LockIcon, guard: false };
        case "mismatch":
            return {
                label: "signed by an UNEXPECTED key",
                detail: `This message was signed by ${groupFpr(v.fingerprint)}, which is not the key bound to ${authorName}${v.expected ? ` (${groupFpr(v.expected)})` : " (no key bound)"}. Treat it as unauthenticated.`,
                tone: "danger", Icon: WarningIcon, guard: true,
            };
        case "unknown-signer":
            return { label: "signed by an unknown key", detail: `Signed by key ${v.keyId}, which is not in your keyring, so the signature could not be checked.`, tone: "warn", Icon: WarningIcon, guard: true };
        case "bad":
            return { label: "INVALID signature", detail: "The signature on this message does not verify. It may have been altered.", tone: "danger", Icon: BrokenLockIcon, guard: true };
        case "unsigned":
            return { label: "not signed", detail: `This message is encrypted but carries no signature, so anyone with ${authorName}'s public key could have written it.`, tone: "warn", Icon: WarningIcon, guard: true };
    }
}

export const modeLabel = (mode: "encrypted" | "signed" | undefined) => mode === "signed" ? "Signed" : "Encrypted";

export const toneClass = (tone: VerdictView["tone"]) => ({
    verified: "vc-pg-verified", self: "vc-pg-self", unverified: "vc-pg-unverified", warn: "vc-pg-warn", danger: "vc-pg-danger",
})[tone];

/**
 * Message footers stay quiet when the signature is fine: muted grey, just "Encrypted" / "Signed". The details
 * live in the tooltip and on the lock next to the username. Anything that needs attention keeps its colour and label.
 */
export const footerClass = (v: VerdictView) => v.guard ? toneClass(v.tone) : undefined;
export const footerText = (prefix: string, v: VerdictView) => v.guard ? `${prefix} · ${v.label}` : prefix;
