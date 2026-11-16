/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Per-attachment encryption state for files sitting in the composer, the hold that stops Discord from
 * uploading them early, and the in-place replacement of a pending upload's File with its encrypted form.
 *
 * Discord calls CloudUpload.upload() the moment a file is added to the draft (UPLOAD_ATTACHMENT_ADD_FILES),
 * so by the time the pre-send hook runs the plaintext would already be on Discord's CDN and the message would
 * merely *reference* it. The patch in index.tsx routes upload() through deferUpload(): in conversations
 * DiscordPG manages the upload stays NOT_STARTED until the hook has encrypted (or deliberately released) the
 * file; Discord's own send queue then calls upload() again for NOT_STARTED files and waits for them.
 */

import { CloudUpload } from "@vencord/discord-types";
import { Logger } from "@utils/Logger";
import { DraftType, UploadAttachmentStore } from "@webpack/common";

import { settings } from "../settings";
import { conversationForId } from "../store/ChannelPrefs";
import { gpgBackend } from "./backend";
import { describeError } from "./backend";
import { ENCRYPTED_EXT, ENCRYPTED_MIME } from "./files";
import { ATTACHMENT_MAX_BYTES, Fingerprint } from "./types";
import { uploadBlocker } from "./uploadPolicy";

const logger = new Logger("DiscordPG");

const PG_UPLOAD = Symbol("DiscordPG.upload");

interface UploadState {
    /** The user's choice for this file (defaults to the encryptAttachmentsByDefault setting). */
    encrypt: boolean;
    /** The plaintext File, kept so a cancelled or failed send can be undone and a toggle-off restores it. */
    original?: File;
    originalName?: string;
    originalMime?: string;
    /** Recipient set (+ signer) the current encrypted File was produced for; lets a retried send skip re-encryption. */
    encryptedFor?: string;
    /** The pre-send hook is done with this file: upload() may proceed. */
    released?: boolean;
}

// ---- the upload hold -------------------------------------------------------------------------------------

let holdPatched = false;
/** Called from the patch's replace callback at patch time: proves the upload hold is in place for this Discord build. */
export function witnessUploadHold() { holdPatched = true; }
export const uploadHoldApplied = () => holdPatched;

/** The files currently attached to the channel's message draft (not slash-command or other drafts). */
export function draftUploads(channelId: string): CloudUpload[] {
    try {
        return UploadAttachmentStore.getUploads(channelId, DraftType.ChannelMessage) ?? [];
    } catch (e) {
        logger.warn("could not read pending uploads", e);
        return [];
    }
}

/**
 * Patched into CloudUpload.upload(): true means "not now". Only in conversations DiscordPG manages, and only
 * until the pre-send hook releases the file. Discord adds the upload to the draft store right *after* the
 * first upload() call, so membership in the message draft is checked a tick later; files that belong to some
 * other draft (slash commands, app launcher) are released immediately.
 */
export function deferUpload(upload: CloudUpload): boolean {
    const st = uploadState(upload);
    if (st.released) return false;
    if (!conversationForId(upload.channelId)) return false;
    setTimeout(() => {
        if (st.released) return;
        if (!draftUploads(upload.channelId).includes(upload)) {
            st.released = true;
            void upload.upload();
        }
    }, 0);
    return true;
}

export function releaseUploads(uploads: CloudUpload[]) {
    for (const u of uploads) uploadState(u).released = true;
}

/** First reason any of these uploads must not be sent yet (see core/uploadPolicy.ts), or null. */
export function uploadsBlocker(uploads: CloudUpload[]): string | null {
    for (const u of uploads) {
        const st = uploadState(u);
        const why = uploadBlocker({ filename: u.filename, status: u.status, encrypt: st.encrypt, touched: !!st.original }, holdPatched);
        if (why) return why;
    }
    return null;
}

type Tagged = CloudUpload & { [PG_UPLOAD]?: UploadState };

export function uploadState(upload: CloudUpload): UploadState {
    const t = upload as Tagged;
    if (!t[PG_UPLOAD]) t[PG_UPLOAD] = { encrypt: settings.store.encryptAttachmentsByDefault };
    return t[PG_UPLOAD]!;
}

export const wantsEncryption = (upload: CloudUpload) => uploadState(upload).encrypt;
export function setUploadEncrypt(upload: CloudUpload, on: boolean) { uploadState(upload).encrypt = on; }

/** Only web-platform uploads carry a File we can read. */
const fileOf = (upload: CloudUpload): File | null => upload.item?.file instanceof File ? upload.item.file : null;

function swapFile(upload: CloudUpload, file: File, filename: string, mime: string) {
    upload.item.file = file;
    upload.filename = filename;
    upload.mimeType = mime;
    upload.preCompressionSize = file.size;
    (upload as any).currentSize = file.size;
}

/** Put the plaintext File back (after a failed/cancelled send, or when the user toggled encryption off). */
export function restoreUpload(upload: CloudUpload) {
    const st = uploadState(upload);
    if (!st.original) return;
    swapFile(upload, st.original, st.originalName ?? st.original.name, st.originalMime ?? st.original.type);
    upload.isImage = st.original.type.startsWith("image/");
    upload.isVideo = st.original.type.startsWith("video/");
    st.original = undefined;
    st.originalName = undefined;
    st.originalMime = undefined;
    st.encryptedFor = undefined;
}

export const restoreUploads = (uploads: CloudUpload[]) => uploads.forEach(restoreUpload);

const planKey = (recipients: Fingerprint[], signWith: Fingerprint | null) => `${recipients.join(",")}|${signWith ?? ""}`;

/**
 * Encrypt every upload whose lock is on, replacing its File in place. Fails closed: on the first problem all
 * uploads are restored and the reason is returned so the send can be cancelled.
 */
export async function encryptUploads(
    uploads: CloudUpload[],
    plan: { recipients: Fingerprint[]; signWith: Fingerprint | null },
): Promise<{ ok: true; count: number } | { ok: false; reason: string }> {
    const key = planKey(plan.recipients, plan.signWith);
    let count = 0;
    for (const upload of uploads) {
        const st = uploadState(upload);
        if (!st.encrypt) { restoreUpload(upload); continue; }
        if (st.original && st.encryptedFor === key) { count++; continue; } // already done on a previous attempt

        const source = st.original ?? fileOf(upload);
        if (!source) { restoreUploads(uploads); return { ok: false, reason: `"${upload.filename}" cannot be read for encryption` }; }
        if (source.size > ATTACHMENT_MAX_BYTES) { restoreUploads(uploads); return { ok: false, reason: `"${upload.filename}" is larger than the ${ATTACHMENT_MAX_BYTES / (1024 * 1024)} MiB DiscordPG limit` }; }
        if (source.size === 0) { restoreUploads(uploads); return { ok: false, reason: `"${upload.filename}" is empty` }; }

        const baseName = st.originalName ?? upload.filename;
        const data = new Uint8Array(await source.arrayBuffer());
        const r = await gpgBackend.encryptAttachment({ data, filename: baseName, recipients: plan.recipients, signWith: plan.signWith });
        if (!r.ok) { restoreUploads(uploads); return { ok: false, reason: `could not encrypt "${baseName}": ${describeError(r.error, r.detail)}` }; }

        if (!st.original) { st.original = source; st.originalName = baseName; st.originalMime = upload.mimeType; }
        const encName = baseName + ENCRYPTED_EXT;
        swapFile(upload, new File([r.data as BlobPart], encName, { type: ENCRYPTED_MIME }), encName, ENCRYPTED_MIME);
        upload.isImage = false;
        upload.isVideo = false;
        st.encryptedFor = key;
        count++;
    }
    return { ok: true, count };
}
