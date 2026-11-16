/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { definePluginSettings } from "@api/Settings";
import { OptionType } from "@utils/types";

export type AutoDecryptMode = "always" | "newOnly" | "manual";

export const settings = definePluginSettings({
    ownKeyFingerprint: {
        type: OptionType.STRING,
        description: "Fingerprint (40 hex) of the secret key used to sign and to read your own sent messages. Pick it in the DiscordPG panel above; this field is informational.",
        default: "",
        placeholder: "not configured",
    },
    signMessages: {
        type: OptionType.BOOLEAN,
        description: "Default for encrypted conversations: sign every encrypted message with your key so recipients can verify it came from you (recommended). Each conversation can override this from the lock icon. With encryption off, signed messages are sent clearsigned (readable text with the signature underneath). Signing requires the YubiKey PIN/touch.",
        default: true,
    },
    requireSignatures: {
        type: OptionType.BOOLEAN,
        description: "Hide decrypted messages that are unsigned or signed by a key other than the sender's bound key behind an explicit warning.",
        default: true,
    },
    encryptByDefault: {
        type: OptionType.BOOLEAN,
        description: "Turn encryption on automatically in a DM once a key is bound to that user.",
        default: true,
    },
    autoDecrypt: {
        type: OptionType.SELECT,
        description: "When to decrypt incoming PGP messages. Each decryption touches the YubiKey (consider the 'cached' touch policy).",
        options: [
            { label: "Always (as messages render)", value: "always", default: true },
            { label: "Only messages received after startup", value: "newOnly" },
            { label: "Manually (click the lock)", value: "manual" },
        ],
    },
    encryptAttachmentsByDefault: {
        type: OptionType.BOOLEAN,
        description: "Start the per-file lock in the composer switched ON, so attachments are encrypted (as .gpg files) unless you unlock them.",
        default: false,
    },
    warnUnencryptedAttachments: {
        type: OptionType.BOOLEAN,
        description: "Ask before sending unencrypted attachments together with an encrypted message.",
        default: true,
    },
    wrapInCodeBlock: {
        type: OptionType.BOOLEAN,
        description: "Wrap the armored ciphertext in a ``` code block so recipients without DiscordPG see a tidy monospace block.",
        default: true,
    },
    hideRecipientKeyIds: {
        type: OptionType.BOOLEAN,
        description: "Hide recipient key IDs in the ciphertext (gpg --throw-keyids). Stronger metadata privacy, but gpg must try every secret key when decrypting, which is slow and prompt-heavy with smartcards.",
        default: false,
    },
    decryptTimeoutSeconds: {
        type: OptionType.NUMBER,
        description: "How long to wait for gpg (including PIN entry and YubiKey touch) before giving up on an operation.",
        default: 120,
    },
    autoLockMinutes: {
        type: OptionType.NUMBER,
        description: "After this many minutes without PGP activity, forget all decrypted text and ask gpg-agent to drop cached PINs. 0 disables.",
        default: 30,
    },
    gpgPath: {
        type: OptionType.STRING,
        description: "Path to the gpg binary. Leave empty to auto-detect. A custom path must be absolute, named gpg/gpg2 and live in a directory your user cannot write to.",
        default: "",
        placeholder: "auto-detect",
    },
});

export const cl = (...parts: Array<string | false | null | undefined>) =>
    parts.filter(Boolean).map(p => `vc-pg-${p}`).join(" ");
