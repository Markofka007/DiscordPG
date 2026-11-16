/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import ErrorBoundary from "@components/ErrorBoundary";
import { getUniqueUsername } from "@utils/discord";
import { Message } from "@vencord/discord-types";
import { Tooltip } from "@webpack/common";

import { describeError } from "../core/backend";
import { useDecryptRecord } from "../store/DecryptStore";
import { BrokenLockIcon, LockIcon, SignatureIcon } from "./icons";
import { describeVerdict, modeLabel, toneClass } from "./verdict";

function Inner({ message }: { message: Message }) {
    const record = useDecryptRecord(message);
    if (!record) return null;

    let Icon = record.detached ? SignatureIcon : LockIcon;
    let cls = "vc-pg-unverified";
    let text = record.detached ? "PGP-signed message" : "Encrypted PGP message";
    switch (record.entry.state) {
        case "pending": text = record.detached ? "Verifying signature…" : "Decrypting…"; break;
        case "error":
            Icon = BrokenLockIcon; cls = record.entry.error === "not-for-you" ? "vc-pg-unverified" : "vc-pg-danger"; text = describeError(record.entry.error, record.entry.detail); break;
        case "ok": {
            const e = record.entry;
            const v = describeVerdict(e.verdict, message.author ? getUniqueUsername(message.author) : "the sender", { channelMismatch: e.channelMismatch, mode: e.mode });
            Icon = v.guard ? v.Icon : e.mode === "signed" ? SignatureIcon : v.Icon;
            cls = toneClass(v.tone); text = `${modeLabel(e.mode)} · ${v.label}\n${v.detail}`; break;
        }
    }

    return (
        <Tooltip text={text}>
            {tooltipProps => (
                <span {...tooltipProps} className={`vc-pg-decoration ${cls}`}>
                    <Icon width={16} height={16} />
                </span>
            )}
        </Tooltip>
    );
}

export const LockDecoration = ErrorBoundary.wrap(Inner, { noop: true });
