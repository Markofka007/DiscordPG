/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { describe, expect, it } from "vitest";

import { hiddenFor } from "../core/display";

describe("hiddenFor (which message states hide Discord's ciphertext row)", () => {
    it("hides while decrypting and once decrypted", () => {
        expect(hiddenFor({ state: "pending" }, false)).toBe(true);
        expect(hiddenFor({ state: "ok" } as any, false)).toBe(true);
    });
    it("keeps the armor visible when idle, failed, or when the user asked for the original", () => {
        expect(hiddenFor({ state: "idle" }, false)).toBe(false);
        expect(hiddenFor({ state: "error", error: "timeout" }, false)).toBe(false);
        expect(hiddenFor({ state: "ok" } as any, true)).toBe(false);
        expect(hiddenFor({ state: "pending" }, true)).toBe(false);
    });
});
