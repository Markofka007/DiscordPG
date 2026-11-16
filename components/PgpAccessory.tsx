/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import ErrorBoundary from "@components/ErrorBoundary";
import { getUniqueUsername } from "@utils/discord";
import { classes } from "@utils/misc";
import { Message, MessageAttachment } from "@vencord/discord-types";
import { findCssClassesLazy } from "@webpack";
import { Parser, SelectedChannelStore, useEffect, UserStore, useState } from "@webpack/common";

import { describeError } from "../core/backend";
import { verdictGuarded } from "../core/display";
import { formatBytes, isImageName, isPgpFileName, isProbeFileName, strippedName } from "../core/files";
import { ARMOR_MAX_BYTES, ATTACHMENT_MAX_BYTES, AttachmentAction, SigVerdict } from "../core/types";
import { extractArmor } from "../core/wire";
import { settings } from "../settings";
import { getAttachment, probeAttachment, processAttachment, retry, toggleOriginal, useDecryptRecord } from "../store/DecryptStore";
import { BrokenLockIcon, KeyIcon, LockIcon, SignatureIcon } from "./icons";
import { openLightbox } from "./Lightbox";
import { openKeyImportModal } from "./modals";
import { describeVerdict, footerClass, footerText, modeLabel } from "./verdict";

/** Discord scopes its list / heading / code styling to the "markup" class; without it lists render as bare lines. */
const MarkupClasses = findCssClassesLazy("markup", "codeContainer");

function authorLabel(message: Message) {
    const u = message.author;
    return u ? getUniqueUsername(u) : "this user";
}

/** "Import key for X" banner for a public key block found in the body or in a probed attachment. */
function KeyBanner({ message, armored, filename }: { message: Message; armored: string; filename?: string }) {
    const me = UserStore.getCurrentUser()?.id;
    if (!message.author || message.author.bot) return null;
    const label = authorLabel(message);
    const own = message.author.id === me;
    return (
        <div className="vc-pg-banner vc-pg-banner-muted">
            <KeyIcon width={16} height={16} />
            <span>PGP public key{filename ? <> <span className="vc-pg-file-name">{filename}</span></> : null}</span>
            {own
                ? <span>(yours)</span>
                : <button className="vc-pg-link" onClick={() => openKeyImportModal(message.author.id, label, armored)}>Import key for {label}</button>}
        </div>
    );
}

/** Offers to import a public key pasted into the message body. (Keys sent as files go through PgpAttachments.) */
function KeyBlockOffer({ message }: { message: Message }) {
    const inline = extractArmor(message.content ?? "", "PUBLIC KEY BLOCK");
    if (!inline || !message.author || message.author.id === UserStore.getCurrentUser()?.id) return null;
    return <div className="vc-pg-accessory"><KeyBanner message={message} armored={inline.armored} /></div>;
}

function VerdictFooter({ verdict, author, extra }: { verdict: SigVerdict; author: string; extra?: React.ReactNode }) {
    const v = describeVerdict(verdict, author);
    return (
        <div className="vc-pg-footer">
            <v.Icon width={14} height={14} className={footerClass(v)} />
            <span className={footerClass(v)} title={v.detail}>{footerText("Encrypted file", v)}</span>
            {extra}
        </div>
    );
}

/** One .gpg / .pgp / .asc attachment: offer Preview (images) / Decrypt & save, then show the outcome. */
function PgpAttachmentRow({ message, att }: { message: Message; att: MessageAttachment }) {
    const entry = getAttachment(message.id, att.id);
    const [revealed, setRevealed] = useState(false);
    const { requireSignatures } = settings.use(["requireSignatures"]);
    const author = authorLabel(message);
    const plain = strippedName(att.filename ?? "");
    const previewable = isImageName(plain);

    const run = (action: AttachmentAction) => void processAttachment(message, att, action);

    const title = (
        <>
            <LockIcon width={16} height={16} />
            <span>Encrypted file <span className="vc-pg-file-name">{att.filename}</span> ({formatBytes(att.size ?? 0)})</span>
        </>
    );
    const actions = (
        <>
            {previewable && <button className="vc-pg-link" onClick={() => run("preview")}>Preview</button>}
            <button className="vc-pg-link" onClick={() => run("save")}>Decrypt &amp; save…</button>
        </>
    );

    switch (entry?.state) {
        case undefined:
        case "message":
            return <div className="vc-pg-banner vc-pg-banner-muted">{title}{actions}</div>;
        case "probing":
            return <div className="vc-pg-banner vc-pg-banner-muted"><KeyIcon width={16} height={16} /><span>Checking <span className="vc-pg-file-name">{att.filename}</span>…</span></div>;
        case "plain":
            return null;
        case "key":
            return <KeyBanner message={message} armored={entry.armored} filename={att.filename} />;
        case "pending":
            return <div className="vc-pg-banner vc-pg-banner-muted">{title}<span>Decrypting… touch your YubiKey if it is blinking.</span></div>;
        case "error": {
            const soft = entry.error === "card-missing" || entry.error === "pin-cancelled" || entry.error === "timeout" || entry.error === "gpg-missing";
            const notForMe = entry.error === "not-for-you";
            return (
                <div className={`vc-pg-banner ${soft || notForMe ? "vc-pg-banner-warn" : "vc-pg-banner-danger"}`}>
                    <BrokenLockIcon width={16} height={16} />
                    <span><span className="vc-pg-file-name">{att.filename}</span>: {describeError(entry.error, entry.detail)}</span>
                    {entry.action && <button className="vc-pg-link" onClick={() => run(entry.action!)}>Retry</button>}
                </div>
            );
        }
        case "saved":
            return (
                <div className="vc-pg-file">
                    <div className="vc-pg-banner vc-pg-banner-muted">{title}<span>Saved to <code>{entry.savedTo}</code></span></div>
                    <VerdictFooter verdict={entry.verdict} author={author} />
                </div>
            );
        case "preview": {
            const guarded = requireSignatures && verdictGuarded(entry.verdict) && !revealed;
            const v = describeVerdict(entry.verdict, author);
            return (
                <div className="vc-pg-file">
                    {guarded ? (
                        <div className={`vc-pg-banner ${v.tone === "danger" ? "vc-pg-banner-danger" : "vc-pg-banner-warn"}`}>
                            <v.Icon width={16} height={16} />
                            <span><b>Hidden:</b> {v.detail}</span>
                            <button className="vc-pg-link" onClick={() => setRevealed(true)}>Show anyway</button>
                        </div>
                    ) : (
                        <div className="vc-pg-preview">
                            <img src={entry.url} alt={plain} onClick={() => openLightbox(message.id, att.id, plain)} />
                        </div>
                    )}
                    <VerdictFooter verdict={entry.verdict} author={author} extra={
                        <>
                            <span>·</span>
                            <span className="vc-pg-file-name">{plain}</span>
                            <span>·</span>
                            {entry.savedTo ? <span>saved to <code>{entry.savedTo}</code></span> : <button className="vc-pg-link" onClick={() => run("save")}>Save…</button>}
                        </>
                    } />
                </div>
            );
        }
    }
}

/** Small .asc / .txt files are probed to find out whether they hold a key or a message; .gpg / .pgp are taken at face value. */
function isCandidate(a: MessageAttachment): boolean {
    const name = a.filename ?? "";
    const size = a.size ?? Infinity;
    if (isPgpFileName(name) && size <= ATTACHMENT_MAX_BYTES) return true;
    return isProbeFileName(name) && size <= ARMOR_MAX_BYTES && size >= 64;
}
const needsProbe = (a: MessageAttachment) => isProbeFileName(a.filename ?? "") && (a.size ?? Infinity) <= ARMOR_MAX_BYTES;

function PgpAttachments({ message }: { message: Message }) {
    const files = (message.attachments ?? []).filter(isCandidate);
    useEffect(() => { for (const a of files) if (needsProbe(a)) probeAttachment(message, a); }, [message.id, files.map(a => a.id).join(",")]);
    if (!files.length) return null;
    const rows = files.map(a => <PgpAttachmentRow key={a.id} message={message} att={a} />);
    return <div className="vc-pg-accessory vc-pg-files">{rows}</div>;
}

function Body({ message, plaintext }: { message: Message; plaintext: string }) {
    // Same parser call Discord itself uses for message content (mirrors MessageLogger's parseEditContent).
    const nodes = Parser.parse(plaintext, true, {
        channelId: message.channel_id,
        messageId: message.id,
        allowLinks: true,
        allowHeading: true,
        allowList: true,
        allowEmojiLinks: true,
        viewingChannelId: SelectedChannelStore.getChannelId(),
    });
    return <div className={classes(MarkupClasses.markup, "vc-pg-body")}>{nodes}</div>;
}

function Inner({ message }: { message: Message }) {
    const record = useDecryptRecord(message);
    return (
        <>
            {record ? <TextPart message={message} record={record} /> : <KeyBlockOffer message={message} />}
            <PgpAttachments message={message} />
        </>
    );
}

function TextPart({ message, record }: { message: Message; record: NonNullable<ReturnType<typeof useDecryptRecord>> }) {
    const [revealed, setRevealed] = useState(false);
    const { requireSignatures } = settings.use(["requireSignatures"]);
    const author = authorLabel(message);
    const e = record.entry;

    switch (e.state) {
        case "idle": {
            const signedOnly = record.detached || extractArmor(message.content ?? "", "SIGNED MESSAGE");
            return (
                <div className="vc-pg-accessory">
                    <div className="vc-pg-banner vc-pg-banner-muted">
                        {signedOnly ? <SignatureIcon width={16} height={16} /> : <LockIcon width={16} height={16} />}
                        <span>{signedOnly ? "PGP-signed message" : "Encrypted PGP message"}</span>
                        <button className="vc-pg-link" onClick={() => retry(message)}>{signedOnly ? "Verify" : "Decrypt"}</button>
                    </div>
                </div>
            );
        }
        case "pending": {
            const signedOnly = record.detached || extractArmor(message.content ?? "", "SIGNED MESSAGE");
            return (
                <div className="vc-pg-accessory">
                    <div className="vc-pg-banner vc-pg-banner-muted">
                        <LockIcon width={16} height={16} />
                        <span>{signedOnly ? "Verifying signature…" : "Decrypting… touch your YubiKey if it is blinking."}</span>
                    </div>
                </div>
            );
        }
        case "error": {
            const soft = e.error === "card-missing" || e.error === "pin-cancelled" || e.error === "timeout" || e.error === "gpg-missing";
            // In a server channel most encrypted messages are for someone else; that is not alarming.
            const quiet = e.error === "not-for-you";
            return (
                <div className="vc-pg-accessory">
                    <div className={`vc-pg-banner ${quiet ? "vc-pg-banner-muted" : soft ? "vc-pg-banner-warn" : "vc-pg-banner-danger"}`}>
                        {quiet ? <LockIcon width={16} height={16} /> : <BrokenLockIcon width={16} height={16} />}
                        <span>{describeError(e.error, e.detail)}</span>
                        <button className="vc-pg-link" onClick={() => retry(message)}>Retry</button>
                    </div>
                </div>
            );
        }
        case "ok": {
            const v = describeVerdict(e.verdict, author, { channelMismatch: e.channelMismatch, mode: e.mode });
            const footer = (
                <div className="vc-pg-footer">
                    <v.Icon width={14} height={14} className={footerClass(v)} />
                    <span className={footerClass(v)} title={v.detail}>{footerText(modeLabel(e.mode), v)}</span>
                    {record.detached && <><span>·</span><span title="The signature follows the text as a separate PGP SIGNATURE block.">detached signature</span></>}
                    <span>·</span>
                    <button className="vc-pg-link" onClick={() => toggleOriginal(message.id)}>
                        {record.showOriginal ? (e.mode === "signed" ? "Show verified text" : "Show decrypted") : "Show original"}
                    </button>
                </div>
            );
            if (record.showOriginal) return <div className="vc-pg-accessory">{footer}</div>;
            if (requireSignatures && v.guard && !revealed) {
                return (
                    <div className="vc-pg-accessory">
                        <div className={`vc-pg-banner ${v.tone === "danger" ? "vc-pg-banner-danger" : "vc-pg-banner-warn"}`}>
                            <v.Icon width={16} height={16} />
                            <span><b>Hidden:</b> {v.detail}</span>
                            <button className="vc-pg-link" onClick={() => setRevealed(true)}>Show anyway</button>
                        </div>
                        {footer}
                    </div>
                );
            }
            return (
                <div className="vc-pg-accessory">
                    <Body message={message} plaintext={e.plaintext} />
                    {footer}
                </div>
            );
        }
    }
}

export const PgpAccessory = ErrorBoundary.wrap(Inner, { noop: true });
