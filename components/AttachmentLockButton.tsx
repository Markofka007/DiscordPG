/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import ErrorBoundary from "@components/ErrorBoundary";
import { CloudUpload } from "@vencord/discord-types";
import { findByCodeLazy } from "@webpack";
import { ChannelStore, useState } from "@webpack/common";

import { setUploadEncrypt, uploadHoldApplied, uploadState } from "../core/uploads";
import { conversationFor } from "../store/ChannelPrefs";
import { BrokenLockIcon, LockIcon, UnlockIcon } from "./icons";

/** Discord's icon button used in the attachment card's utility row (spoiler / edit / remove). */
const ActionBarIcon = findByCodeLazy("Children.map", "isValidElement", "dangerous:");

/** Per-file lock in the composer's attachment card. Same insertion point Vencord's AnonymiseFileNames uses. */
export const AttachmentLockButton = ErrorBoundary.wrap(({ upload }: { upload: CloudUpload }) => {
    const [on, setOn] = useState(() => uploadState(upload).encrypt);
    if (!conversationFor(ChannelStore.getChannel(upload.channelId))) return null;

    const toggle = () => {
        setUploadEncrypt(upload, !on);
        setOn(!on);
    };
    if (!uploadHoldApplied()) {
        return (
            <ActionBarIcon tooltip="DiscordPG cannot encrypt attachments on this Discord build: Discord uploads files before DiscordPG can encrypt them. Unlock this file or remove it." onClick={toggle}>
                <BrokenLockIcon className="vc-pg-upload-off" />
            </ActionBarIcon>
        );
    }
    return (
        <ActionBarIcon
            tooltip={on ? "Will be PGP-encrypted (.gpg) for this conversation's keys — click to send it unencrypted" : "Will be sent UNENCRYPTED — click to encrypt it"}
            onClick={toggle}
        >
            {on ? <LockIcon className="vc-pg-upload-on" /> : <UnlockIcon className="vc-pg-upload-off" />}
        </ActionBarIcon>
    );
}, { noop: true });
