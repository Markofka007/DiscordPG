/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { IconComponent, IconProps } from "@utils/types";

type P = IconProps;

export const LockIcon: IconComponent = ({ height = 20, width = 20, className }: P) => (
    <svg viewBox="0 0 24 24" height={height} width={width} className={className} aria-hidden="true">
        <path fill="currentColor" d="M17 9h-1V7a4 4 0 1 0-8 0v2H7a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-9a2 2 0 0 0-2-2Zm-7-2a2 2 0 1 1 4 0v2h-4V7Zm2 10a1.5 1.5 0 1 1 0-3 1.5 1.5 0 0 1 0 3Z" />
    </svg>
);

export const UnlockIcon: IconComponent = ({ height = 20, width = 20, className }: P) => (
    <svg viewBox="0 0 24 24" height={height} width={width} className={className} aria-hidden="true">
        <path fill="currentColor" d="M17 9H10V7a2 2 0 0 1 4 0h2a4 4 0 1 0-8 0v2H7a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-9a2 2 0 0 0-2-2Zm-5 8a1.5 1.5 0 1 1 0-3 1.5 1.5 0 0 1 0 3Z" />
    </svg>
);

export const BrokenLockIcon: IconComponent = ({ height = 20, width = 20, className }: P) => (
    <svg viewBox="0 0 24 24" height={height} width={width} className={className} aria-hidden="true">
        <path fill="currentColor" d="M17 9h-1V7a4 4 0 0 0-6.3-3.3l1.5 1.5A2 2 0 0 1 14 7v2h-4.2l-5-5L3.4 5.4 18.6 20.6 20 19.2l-1-1V11a2 2 0 0 0-2-2ZM5 11v9a2 2 0 0 0 2 2h9.2L5.4 11.2A2 2 0 0 0 5 11Z" />
    </svg>
);

export const WarningIcon: IconComponent = ({ height = 20, width = 20, className }: P) => (
    <svg viewBox="0 0 24 24" height={height} width={width} className={className} aria-hidden="true">
        <path fill="currentColor" d="M12 2 1 21h22L12 2Zm1 15h-2v-2h2v2Zm0-4h-2V9h2v4Z" />
    </svg>
);

export const KeyIcon: IconComponent = ({ height = 20, width = 20, className }: P) => (
    <svg viewBox="0 0 24 24" height={height} width={width} className={className} aria-hidden="true">
        <path fill="currentColor" d="M7 14a2 2 0 1 1 0-4 2 2 0 0 1 0 4Zm0-8a6 6 0 0 0 5.65 8H14l2 2 2-2 2 2 3-3-2-2h-8.35A6 6 0 0 0 7 6Z" />
    </svg>
);

/** Signed but not encrypted. */
export const SignatureIcon: IconComponent = ({ height = 20, width = 20, className }: P) => (
    <svg viewBox="0 0 24 24" height={height} width={width} className={className} aria-hidden="true">
        <path fill="currentColor" d="M3 17.25V21h3.75L17.8 9.94l-3.75-3.75L3 17.25Zm2 .83 9.06-9.06 1.92 1.92L6.92 20H5v-1.92ZM20.7 7.04a1 1 0 0 0 0-1.41l-2.34-2.34a1 1 0 0 0-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83ZM3 22h18v1H3z" />
    </svg>
);
