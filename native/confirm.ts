/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Native (main-process) confirmation dialogs. These are the one UI the renderer
 * cannot draw, spoof or auto-click, which is why every trust decision goes
 * through here.
 */

import { app, BrowserWindow, dialog } from "electron";
import { writeFile } from "fs/promises";
import { join } from "path";

import { Fingerprint } from "../core/types";

export const groupFingerprint = (f: Fingerprint) => f.replace(/(.{4})/g, "$1 ").trim();

function parentWindow(): BrowserWindow | undefined {
    return BrowserWindow.getFocusedWindow() ?? BrowserWindow.getAllWindows()[0];
}

async function ask(opts: { type: "question" | "warning"; message: string; detail: string; confirmLabel: string }): Promise<boolean> {
    const win = parentWindow();
    const box: Electron.MessageBoxOptions = {
        type: opts.type,
        title: "DiscordPG",
        message: opts.message,
        detail: opts.detail,
        buttons: ["Cancel", opts.confirmLabel],
        defaultId: 0,
        cancelId: 0,
        noLink: true,
    };
    const { response } = win ? await dialog.showMessageBox(win, box) : await dialog.showMessageBox(box);
    return response === 1;
}

export function confirmBind(p: { userLabel: string; userId: string; fingerprint: Fingerprint; previous: Fingerprint | null }): Promise<boolean> {
    if (p.previous) {
        return ask({
            type: "warning",
            message: `Key CHANGE for ${p.userLabel}`,
            detail:
                `This Discord user previously had a different PGP key. A changed key can mean they rotated keys, or that someone is impersonating them.\n\n` +
                `Old fingerprint:\n${groupFingerprint(p.previous)}\n\nNew fingerprint:\n${groupFingerprint(p.fingerprint)}\n\n` +
                `User ID: ${p.userId}\n\nOnly continue if you have confirmed the new fingerprint with them through another channel.`,
            confirmLabel: "Replace key",
        });
    }
    return ask({
        type: "question",
        message: `Trust this PGP key for ${p.userLabel}?`,
        detail:
            `DiscordPG will encrypt your messages to this user with the key below and treat messages signed by it as theirs.\n\n` +
            `Fingerprint:\n${groupFingerprint(p.fingerprint)}\n\nUser ID: ${p.userId}\n\n` +
            `It will be marked "unverified" until you compare the fingerprint with them out of band.`,
        confirmLabel: "Trust key",
    });
}

export function confirmVerify(p: { userLabel: string; userId: string; fingerprint: Fingerprint }): Promise<boolean> {
    return ask({
        type: "question",
        message: `Mark ${p.userLabel}'s key as verified?`,
        detail:
            `Only do this after comparing the full fingerprint with them in person, by voice, or over another channel you trust.\n\n` +
            `Fingerprint:\n${groupFingerprint(p.fingerprint)}\n\nUser ID: ${p.userId}`,
        confirmLabel: "I compared it, mark verified",
    });
}

export function confirmUnbind(p: { userLabel: string; userId: string; fingerprint: Fingerprint }): Promise<boolean> {
    return ask({
        type: "question",
        message: `Forget ${p.userLabel}'s PGP key?`,
        detail: `Nothing can be encrypted to this user until a key is bound again. Conversations with them that had encryption on will refuse to send until then, unless you turn encryption off there.\n\nFingerprint:\n${groupFingerprint(p.fingerprint)}\n\nUser ID: ${p.userId}`,
        confirmLabel: "Forget key",
    });
}

/** Sign-only mode is a signing oracle for anything running in Discord's renderer; the user enables it per session. */
export function confirmSignOnly(p: { fingerprint: Fingerprint }): Promise<boolean> {
    return ask({
        type: "question",
        message: "Allow DiscordPG to sign unencrypted messages?",
        detail:
            `A conversation has "Sign messages" on while encryption is off, so the message text would be signed in the clear with your key\n\n` +
            `${groupFingerprint(p.fingerprint)}\n\n` +
            `This permission lasts until Discord restarts or you lock DiscordPG (/pgp lock). Every signature still goes through gpg-agent ` +
            `(PIN / YubiKey touch), is limited to short text, is rate limited, and carries a note naming the Discord channel it was made for.`,
        confirmLabel: "Allow for this session",
    });
}

/**
 * Write a decrypted attachment where the user chooses. `warning` (unsigned / wrong signer) is shown first as
 * an OS dialog so the renderer cannot talk the user past it. Returns the path or null when cancelled.
 */
export async function saveDecryptedFile(p: { suggestedName: string; bytes: Buffer; warning: string | null }): Promise<string | null> {
    if (p.warning) {
        const go = await ask({
            type: "warning",
            message: `Save "${p.suggestedName}" although its sender could not be confirmed?`,
            detail: `${p.warning}\n\nThe file decrypted correctly, but this signature verdict means you cannot be sure who produced it.`,
            confirmLabel: "Save anyway",
        });
        if (!go) return null;
    }
    const win = parentWindow();
    const opts: Electron.SaveDialogOptions = {
        title: "DiscordPG: save decrypted file",
        defaultPath: join(app.getPath("downloads"), p.suggestedName),
        properties: ["createDirectory", "showOverwriteConfirmation"],
    };
    const { canceled, filePath } = win ? await dialog.showSaveDialog(win, opts) : await dialog.showSaveDialog(opts);
    if (canceled || !filePath) return null;
    await writeFile(filePath, p.bytes, { mode: 0o600 });
    return filePath;
}
