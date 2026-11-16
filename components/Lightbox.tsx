/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Full-screen viewer for a decrypted image preview. Discord's own media viewer is not used on purpose: it
 * expects CDN URLs (it rewrites them for the media proxy and offers "open in browser"), while a preview is a
 * blob: URL over plaintext that must never leave this window. The behaviour mirrors it instead: click the
 * image to zoom in / out, scroll to zoom, drag to pan, click outside or press Escape to close.
 */

import { RenderModalProps } from "@vencord/discord-types";
import { openModal, useEffect, useRef, useState } from "@webpack/common";

import { getAttachment, subscribe } from "../store/DecryptStore";

const MAX_SCALE = 8;
const CLICK_SCALE = 2;
const DRAG_THRESHOLD = 4;
/** Discord's ModalTransitionState: 0 entering, 1 entered, 2 exiting, 3 exited, 4 hidden. */
const TRANSITION_EXITING = 2;

interface View { scale: number; x: number; y: number }
const FIT: View = { scale: 1, x: 0, y: 0 };

function Lightbox({ rootProps, messageId, attachmentId, name }: { rootProps: RenderModalProps; messageId: string; attachmentId: string; name: string }) {
    const [, bump] = useState(0);
    const [view, setView] = useState<View>(FIT);
    const [dragging, setDragging] = useState(false);
    const drag = useRef<{ px: number; py: number; x: number; y: number; moved: boolean } | null>(null);

    // The preview lives exactly as long as the plaintext does: locking revokes the blob URL, and an already
    // painted <img> would otherwise stay on screen.
    useEffect(() => subscribe(messageId, () => bump(n => n + 1)), [messageId]);
    const entry = getAttachment(messageId, attachmentId);
    const url = entry?.state === "preview" ? entry.url : null;
    useEffect(() => { if (!url) rootProps.onClose(); }, [url]);
    if (!url) return null;

    /** Change the zoom while keeping the image point under the cursor where it is. */
    const zoomAt = (e: { clientX: number; clientY: number; currentTarget: Element }, target: number) => {
        const scale = Math.min(MAX_SCALE, Math.max(1, target));
        if (scale === 1) return setView(FIT);
        const r = e.currentTarget.getBoundingClientRect();
        const px = e.clientX - (r.left + r.width / 2), py = e.clientY - (r.top + r.height / 2);
        setView(v => ({ scale, x: v.x + px * (1 - scale / v.scale), y: v.y + py * (1 - scale / v.scale) }));
    };

    const zoomed = view.scale > 1;
    // Discord keeps a closing modal mounted for its exit animation. Normally ModalRoot plays that animation;
    // we render our own overlay, so without this the image would sit there, swallowing clicks, until unmount.
    const closing = rootProps.transitionState >= TRANSITION_EXITING;
    return (
        <div className={closing ? "vc-pg-lightbox vc-pg-lightbox-closing" : "vc-pg-lightbox"} onClick={rootProps.onClose}>
            <button className="vc-pg-lightbox-close" aria-label="Close" autoFocus onClick={rootProps.onClose}>✕</button>
            <img
                src={url}
                alt={name}
                draggable={false}
                className={dragging ? "vc-pg-lightbox-grabbing" : zoomed ? "vc-pg-lightbox-zoomed" : undefined}
                style={{ transform: `translate(${view.x}px, ${view.y}px) scale(${view.scale})`, transition: dragging ? "none" : undefined }}
                onClick={e => {
                    e.stopPropagation();
                    if (drag.current?.moved) return;
                    zoomAt(e, zoomed ? 1 : CLICK_SCALE);
                }}
                onWheel={e => zoomAt(e, view.scale * (e.deltaY < 0 ? 1.2 : 1 / 1.2))}
                onPointerDown={e => {
                    if (e.button !== 0) return;
                    drag.current = { px: e.clientX, py: e.clientY, x: view.x, y: view.y, moved: false };
                    e.currentTarget.setPointerCapture(e.pointerId);
                }}
                onPointerMove={e => {
                    const d = drag.current;
                    if (!d || !(e.buttons & 1) || !zoomed) return;
                    const dx = e.clientX - d.px, dy = e.clientY - d.py;
                    if (!d.moved && Math.hypot(dx, dy) < DRAG_THRESHOLD) return;
                    d.moved = true;
                    setDragging(true);
                    setView(v => ({ ...v, x: d.x + dx, y: d.y + dy }));
                }}
                onPointerUp={() => setDragging(false)}
                onPointerCancel={() => setDragging(false)}
            />
            <div className="vc-pg-lightbox-caption" onClick={e => e.stopPropagation()}>{name}</div>
        </div>
    );
}

export function openLightbox(messageId: string, attachmentId: string, name: string) {
    openModal(props => <Lightbox rootProps={props} messageId={messageId} attachmentId={attachmentId} name={name} />);
}
