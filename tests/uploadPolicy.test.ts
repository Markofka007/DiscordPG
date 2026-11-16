/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { describe, expect, it } from "vitest";

import { uploadBlocker } from "../core/uploadPolicy";

const f = (over: Partial<Parameters<typeof uploadBlocker>[0]> = {}) =>
    ({ filename: "pic.png", status: "NOT_STARTED" as const, encrypt: true, touched: false, ...over });

describe("uploadBlocker (never let Discord attach bytes we did not produce)", () => {
    it("allows a locked file that Discord has not started uploading, with the hold in place", () => {
        expect(uploadBlocker(f(), true)).toBeNull();
    });
    it("blocks a locked file once Discord has uploaded it (any non-NOT_STARTED status)", () => {
        for (const status of ["STARTED", "UPLOADING", "COMPLETED", "ERROR"] as const) {
            expect(uploadBlocker(f({ status }), true)).toMatch(/already uploaded/);
        }
    });
    it("blocks a previously encrypted file that was unlocked again after Discord uploaded it", () => {
        expect(uploadBlocker(f({ encrypt: false, touched: true, status: "COMPLETED" }), true)).toMatch(/restored/);
        expect(uploadBlocker(f({ encrypt: false, touched: true }), true)).toBeNull();
    });
    it("never blocks a plain, untouched file (that is Discord's normal behaviour)", () => {
        expect(uploadBlocker(f({ encrypt: false, status: "COMPLETED" }), true)).toBeNull();
        expect(uploadBlocker(f({ encrypt: false, status: "COMPLETED" }), false)).toBeNull();
    });
    it("blocks every locked file when the upload hold patch did not apply", () => {
        expect(uploadBlocker(f(), false)).toMatch(/upload hold did not apply/);
    });
});
