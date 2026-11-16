/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Pure rules for attachments at send time. Background: Discord starts uploading a file the moment it is
 * dropped into the composer, long before the pre-send hook runs. DiscordPG therefore holds uploads back
 * (`deferUpload` in core/uploads.ts) in conversations it manages, encrypts the locked ones in the hook, and
 * only then lets Discord upload. These checks make the hook fail closed when that hold did not happen.
 */

export type UploadStatus = "NOT_STARTED" | "STARTED" | "UPLOADING" | "ERROR" | "COMPLETED" | "CANCELLED" | "REMOVED_FROM_MSG_DRAFT";

export interface UploadFacts {
    filename: string;
    status: UploadStatus;
    /** The lock is on for this file. */
    encrypt: boolean;
    /** The file was encrypted on an earlier (failed) attempt, i.e. we have swapped its bytes before. */
    touched: boolean;
}

/**
 * Why this upload must NOT be sent right now, or null when it is fine. A locked (or previously swapped) file
 * whose upload already left NOT_STARTED has had its *current* bytes sent to Discord's CDN by Discord itself,
 * so swapping the File object would silently attach the wrong content under the wrong name.
 */
export function uploadBlocker(u: UploadFacts, patchApplied: boolean): string | null {
    if (!u.encrypt && !u.touched) return null; // plain file Discord may handle as usual
    if (!patchApplied) return `"${u.filename}" cannot be encrypted: DiscordPG's upload hold did not apply to this Discord build (Discord uploads files before DiscordPG can encrypt them). Unlock it or remove it.`;
    if (u.status !== "NOT_STARTED") return `"${u.filename}" was already uploaded by Discord before it could be ${u.encrypt ? "encrypted" : "restored"}. Remove it from the message and add it again.`;
    return null;
}
