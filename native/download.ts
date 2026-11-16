/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Downloads an attachment from Discord's CDN in the main process. The URL has already passed
 * schema.attachmentUrl (https, Discord CDN hosts, /attachments/ path), and this helper adds the rest of the
 * guard rails: no redirects (a redirect could leave the allow-listed host), no cookies or credentials, a
 * hard byte cap enforced while streaming, and a timeout. Uses Electron's `net` so system proxy settings apply.
 */

import { net } from "electron";

export class DownloadError extends Error {
    constructor(message: string, public readonly oversize = false) {
        super(message);
        this.name = "DownloadError";
    }
}

export function download(url: string, maxBytes: number, timeoutMs = 60_000): Promise<Buffer> {
    return new Promise<Buffer>((resolve, reject) => {
        const chunks: Buffer[] = [];
        let received = 0;
        let done = false;
        const finish = (fn: () => void) => { if (!done) { done = true; clearTimeout(timer); fn(); } };

        const req = net.request({ url, method: "GET", redirect: "error", useSessionCookies: false, credentials: "omit" });
        const timer = setTimeout(() => { finish(() => reject(new DownloadError("timed out"))); req.abort(); }, timeoutMs);

        req.on("response", res => {
            if (res.statusCode !== 200) {
                finish(() => reject(new DownloadError(`HTTP ${res.statusCode}`)));
                req.abort();
                return;
            }
            const declared = Number(res.headers["content-length"] ?? 0);
            if (declared > maxBytes) {
                finish(() => reject(new DownloadError("too large", true)));
                req.abort();
                return;
            }
            res.on("data", (chunk: Buffer) => {
                received += chunk.length;
                if (received > maxBytes) {
                    finish(() => reject(new DownloadError("too large", true)));
                    req.abort();
                    return;
                }
                chunks.push(chunk);
            });
            res.on("end", () => finish(() => resolve(Buffer.concat(chunks))));
            res.on("error", (e: Error) => finish(() => reject(new DownloadError(e.message))));
            res.on("aborted", () => finish(() => reject(new DownloadError("aborted"))));
        });
        req.on("redirect", () => { finish(() => reject(new DownloadError("unexpected redirect"))); req.abort(); });
        req.on("error", e => finish(() => reject(new DownloadError(e.message))));
        req.on("abort", () => finish(() => reject(new DownloadError("aborted"))));
        req.end();
    });
}
