/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import "./styles.css";

import { addMessageAccessory, removeMessageAccessory } from "@api/MessageAccessories";
import { ApplicationCommandInputType, ApplicationCommandOptionType, findOption, sendBotMessage } from "@api/Commands";
import { findGroupChildrenByChildId, NavContextMenuPatchCallback } from "@api/ContextMenu";
import { showNotice } from "@api/Notices";
import { copyWithToast, getUniqueUsername, sendMessage } from "@utils/discord";
import { Logger } from "@utils/Logger";
import definePlugin from "@utils/types";
import { CloudUpload, Message, User } from "@vencord/discord-types";
import { findByProps } from "@webpack";
import { Menu, MessageStore, showToast, UploadHandler, UserStore } from "@webpack/common";

import { AttachmentLockButton } from "./components/AttachmentLockButton";
import { openConversationSettings } from "./components/ConversationSettings";
import { LockIcon } from "./components/icons";
import { LockDecoration } from "./components/LockDecoration";
import { openFingerprintModal, openGroupKeysModal, openKeyImportModal } from "./components/modals";
import { PgpAccessory } from "./components/PgpAccessory";
import { PgpChatBarButton } from "./components/PgpChatBarButton";
import { SettingsPanel } from "./components/SettingsPanel";
import { checkNativeVersion, describeError, gpgBackend } from "./core/backend";
import { checkEditHook, checkSendHook, HOOK_FINDS, HOOK_MARKERS, witnessHook } from "./core/integrity";
import { onBeforeMessageEdit, onBeforeMessageSend, userName } from "./core/send";
import { FINGERPRINT_RE } from "./core/types";
import { deferUpload, witnessUploadHold } from "./core/uploads";
import { discordContentLimit, extractArmor, wrapForDiscord } from "./core/wire";
import { settings } from "./settings";
import { getBinding, refreshBindings } from "./store/Bindings";
import { loadChannelPrefs, policyFor, setEncrypt, setSign } from "./store/ChannelPrefs";
import { clearAll, ensure, evict, getRecord, isHidden, retry, toggleOriginal } from "./store/DecryptStore";
import { lockNow, startAutoLock, stopAutoLock } from "./store/lock";

const logger = new Logger("DiscordPG");

const userContextPatch: NavContextMenuPatchCallback = (children, { user }: { user?: User }) => {
    if (!user || user.bot || user.id === UserStore.getCurrentUser()?.id) return;
    const label = getUniqueUsername(user);
    const binding = getBinding(user.id);
    children.push(
        <Menu.MenuGroup>
            <Menu.MenuItem id="vc-pg-user" label="DiscordPG" icon={LockIcon} leadingAccessory={{ type: "icon", icon: LockIcon }}>
                <Menu.MenuItem id="vc-pg-user-fpr" label={binding ? `Fingerprints (${binding.verified ? "verified" : "unverified"})` : "Fingerprints"} action={() => openFingerprintModal(user.id, label)} />
                <Menu.MenuItem id="vc-pg-user-import" label={binding ? "Replace key…" : "Import key…"} action={() => openKeyImportModal(user.id, label)} />
            </Menu.MenuItem>
        </Menu.MenuGroup>
    );
};

const messageContextPatch: NavContextMenuPatchCallback = (children, { message }: { message?: Message }) => {
    if (!message) return;
    const record = getRecord(message.id);
    if (!record || record.entry.state !== "ok") return;
    const { plaintext } = record.entry;
    const group = findGroupChildrenByChildId("copy-text", children) ?? children;
    group.push(
        <Menu.MenuItem id="vc-pg-copy-plain" label="Copy decrypted text" action={() => copyWithToast(plaintext, "Decrypted text copied")} />
    );
};

let origStartEdit: ((channelId: string, messageId: string, content: string) => unknown) | null = null;
let MessageActionsModule: any = null;

export default definePlugin({
    name: "DiscordPG",
    description: "Discord Privacy Guard: GnuPG end-to-end encryption and signing for DMs, group DMs and server channels, plus encrypted attachments. Your keys stay in gpg-agent / your YubiKey; messages fail closed.",
    authors: [{ name: "marko", id: 0n }],
    enabledByDefault: true,
    tags: ["Chat", "Utility"],
    searchTerms: ["pgp", "gpg", "gnupg", "encryption", "privacy", "e2e", "yubikey"],
    settings,
    settingsAboutComponent: SettingsPanel,
    dependencies: ["MessageUpdaterAPI", "MessageAccessoriesAPI"],

    patches: [
        {
            // Add a class to the message <li> while we show plaintext, so CSS can hide Discord's rendering of the ciphertext.
            find: "Message must not be a thread starter message",
            replacement: {
                match: /\)\("li",\{(.+?),className:/,
                replace: ")(\"li\",{$1,className:$self.liClass(arguments[0]?.message)+",
            },
        },
        {
            // Per-file lock in the composer's attachment card (same spot as Vencord's AnonymiseFileNames button).
            find: "#{intl::ATTACHMENT_UTILITIES_SPOILER}",
            replacement: {
                match: /(?<=children:\[)(?=.{10,200}tooltip:.{0,100}#{intl::ATTACHMENT_UTILITIES_SPOILER})/,
                replace: "arguments[0].canEdit!==false?$self.AttachmentLockButton(arguments[0]):null,",
            },
        },
        {
            // Discord starts uploading a file the moment it is added to the composer, i.e. before the pre-send hook
            // could encrypt it. Hold uploads in conversations DiscordPG manages until the hook releases them.
            find: "uploadFileToCloud",
            replacement: {
                match: /async upload\(\)\{if\("COMPLETED"===this\.status\)return;/,
                replace: m => { witnessUploadHold(); return `${m}if($self.deferUpload(this))return;`; },
            },
        },
        // Witness patches (see core/integrity.ts): they change nothing, they only prove at patch time that
        // MessageEventsAPI's pre-send / pre-edit hooks were injected into Discord's code before ours ran.
        {
            find: HOOK_FINDS.send,
            replacement: { match: HOOK_MARKERS.send, replace: m => { witnessHook("send"); return m; }, noWarn: true },
        },
        {
            find: HOOK_FINDS.edit,
            replacement: { match: HOOK_MARKERS.edit, replace: m => { witnessHook("edit"); return m; }, noWarn: true },
        },
    ],

    AttachmentLockButton,

    deferUpload(upload: CloudUpload): boolean {
        try {
            return deferUpload(upload);
        } catch (e) {
            logger.error("deferUpload failed", e);
            return false;
        }
    },

    liClass(message?: Message) {
        try {
            if (!message) return "";
            // The <li> renders before the accessory's effects run, so create the record (and start decrypting /
            // apply the optimistic plaintext) right here; otherwise the first paint always shows the armor.
            ensure(message);
            return isHidden(message.id) ? "vc-pg-hidden " : "";
        } catch {
            return "";
        }
    },

    async start() {
        // Registered by hand rather than via `renderMessageAccessory`, which always appends: position 0 puts the
        // plaintext where the hidden message content was, i.e. above Discord's own accessories (attachments,
        // embeds, reactions) instead of below the reactions.
        addMessageAccessory("DiscordPG", props => props.isMessageSnapshot ? null : <PgpAccessory message={props.message} />, 0);

        if (await checkNativeVersion() === "stale") {
            showNotice("DiscordPG: Discord's main process is running a different DiscordPG build than this window (Ctrl+R only reloads the window). Fully quit Discord and start it again.", "OK", () => { });
        }
        await loadChannelPrefs();
        await refreshBindings();
        startAutoLock();

        // Edit box prefill: open the editor with the plaintext instead of the armor.
        try {
            MessageActionsModule = findByProps("deleteMessage", "startEditMessage");
            ({ startEditMessage: origStartEdit } = MessageActionsModule);
            MessageActionsModule.startEditMessage = (channelId: string, messageId: string, content: string) => {
                const r = getRecord(messageId);
                if (r?.entry.state !== "ok") return origStartEdit!.call(MessageActionsModule, channelId, messageId, content);
                const { plaintext } = r.entry;
                const open = (c: string) => origStartEdit!.call(MessageActionsModule, channelId, messageId, c);
                const status = checkEditHook();
                if (status === "ok") return open(plaintext);
                if (status === "broken") {
                    showToast({ text: "DiscordPG: Vencord's edit hook is missing, so editing encrypted messages is disabled. Restart Discord; if it persists, update Vencord.", variant: "critical" });
                    return open(content);
                }
                // The edit-box module has not run yet, so it cannot have been patched yet. Open it with the
                // ciphertext (safe either way), then swap in the plaintext once the witness confirms the hook.
                const res = open(content);
                setTimeout(() => {
                    if (checkEditHook() === "ok") open(plaintext);
                    else showToast({ text: "DiscordPG: could not confirm Vencord's edit hook; editing the ciphertext only.", variant: "critical" });
                }, 0);
                return res;
            };
        } catch (e) {
            logger.warn("could not wrap startEditMessage", e);
        }

        if (!FINGERPRINT_RE.test(settings.store.ownKeyFingerprint)) {
            showNotice("DiscordPG: no own key selected yet. Pick it in Settings → Plugins → DiscordPG.", "OK", () => { });
        }
        // Delayed integrity check: the composer chunk is only present once a chat is open.
        setTimeout(() => {
            if (checkSendHook() === "broken") {
                showNotice("DiscordPG: Vencord's message send hook is missing. Encrypted conversations would go out as PLAINTEXT, so encryption is disabled. Restart Discord first (patches only apply at startup); if it persists, update Vencord.", "Understood", () => { });
            }
        }, 15_000);
    },

    stop() {
        removeMessageAccessory("DiscordPG");
        stopAutoLock();
        clearAll();
        if (MessageActionsModule && origStartEdit) MessageActionsModule.startEditMessage = origStartEdit;
        origStartEdit = null;
    },

    flux: {
        MESSAGE_DELETE({ id }: { id: string }) { evict(id); },
        MESSAGE_DELETE_BULK({ ids }: { ids: string[] }) { ids?.forEach(evict); },
        MESSAGE_UPDATE({ message }: { message: { id: string; channel_id: string } }) {
            const m = MessageStore.getMessage(message.channel_id, message.id);
            if (m && getRecord(m.id)) ensure(m);
        },
    },

    onBeforeMessageSend,
    onBeforeMessageEdit,

    renderMessageDecoration: props => <LockDecoration message={props.message} />,

    chatBarButton: { icon: LockIcon, render: PgpChatBarButton },

    messagePopoverButton: {
        icon: LockIcon,
        render(message: Message) {
            const record = getRecord(message.id);
            if (record?.entry.state === "ok" && !record.detached) {
                return {
                    label: record.showOriginal ? (record.entry.mode === "signed" ? "Show verified text" : "Show decrypted text") : "Show original block",
                    icon: LockIcon,
                    onClick: () => toggleOriginal(message.id),
                };
            }
            if (record && (record.entry.state === "idle" || record.entry.state === "error")) {
                return { label: record.detached ? "Verify signature" : "Decrypt", icon: LockIcon, onClick: () => retry(message) };
            }
            const me = UserStore.getCurrentUser()?.id;
            const key = extractArmor(message.content ?? "", "PUBLIC KEY BLOCK");
            if (key && message.author && message.author.id !== me) {
                return { label: "Import PGP key", icon: LockIcon, onClick: () => openKeyImportModal(message.author.id, getUniqueUsername(message.author), key.armored) };
            }
            return null;
        },
    },

    contextMenus: {
        "user-context": userContextPatch,
        "message": messageContextPatch,
    },

    commands: [
        {
            name: "pgp",
            description: "DiscordPG: PGP encryption and signing for this conversation",
            inputType: ApplicationCommandInputType.BUILT_IN,
            options: [
                { name: "share", description: "Post your public key in this channel", type: ApplicationCommandOptionType.SUB_COMMAND, options: [] },
                { name: "status", description: "Show the encryption / signing status of this conversation", type: ApplicationCommandOptionType.SUB_COMMAND, options: [] },
                { name: "settings", description: "Open the DiscordPG settings for this conversation", type: ApplicationCommandOptionType.SUB_COMMAND, options: [] },
                { name: "on", description: "Turn encryption on for this conversation", type: ApplicationCommandOptionType.SUB_COMMAND, options: [] },
                { name: "off", description: "Turn encryption off for this conversation", type: ApplicationCommandOptionType.SUB_COMMAND, options: [] },
                {
                    name: "sign", description: "Sign messages in this conversation", type: ApplicationCommandOptionType.SUB_COMMAND,
                    options: [{ name: "state", description: "on, off, or default", type: ApplicationCommandOptionType.STRING, required: true, choices: [{ name: "on", value: "on", label: "on" }, { name: "off", value: "off", label: "off" }, { name: "default", value: "default", label: "default" }] }],
                },
                { name: "fingerprint", description: "Show fingerprints (yours and the members')", type: ApplicationCommandOptionType.SUB_COMMAND, options: [] },
                { name: "lock", description: "Forget all decrypted text and drop the PIN cache", type: ApplicationCommandOptionType.SUB_COMMAND, options: [] },
            ],
            async execute(args, ctx) {
                const { channel } = ctx;
                const reply = (content: string) => { sendBotMessage(channel.id, { content }); };
                const sub = args[0]?.name;
                const subOpts = args[0]?.options ?? [];
                const own = settings.store.ownKeyFingerprint;
                const policy = policyFor(channel.id);
                const conv = policy?.conv ?? null;
                const keys = policy?.keys ?? null;
                const notDm = "DiscordPG works in DMs, group DMs and server text channels.";

                switch (sub) {
                    case "share": {
                        if (!FINGERPRINT_RE.test(own)) return reply("No own key selected. Open Settings → Plugins → DiscordPG.");
                        const r = await gpgBackend.exportPublicKey(own);
                        if (!r.ok) return reply(describeError(r.error, r.detail));
                        const wire = wrapForDiscord(r.armored, true);
                        if (wire.length <= discordContentLimit(UserStore.getCurrentUser()?.premiumType)) {
                            sendMessage(channel.id, { content: wire });
                        } else {
                            const file = new File([r.armored], "publickey.asc", { type: "text/plain" });
                            UploadHandler.promptToUpload([file], channel, 0);
                        }
                        return;
                    }
                    case "status": {
                        if (!policy || !conv || !keys) return reply(notDm);
                        const memberLine = (id: string) => {
                            const b = getBinding(id);
                            return `• ${userName(id)}: ${b ? `\`${b.fingerprint}\` (${b.verified ? "verified" : "**unverified**"})` : "**no key bound**"}`;
                        };
                        const head = conv.kind === "dm" ? `**DiscordPG status for ${userName(conv.recipientIds[0])}**`
                            : conv.kind === "group" ? `**DiscordPG status for this group (${conv.recipientIds.length} members)**`
                                : `**DiscordPG status for #${channel.name} (${conv.recipientIds.length} chosen recipient${conv.recipientIds.length === 1 ? "" : "s"})**`;
                        const lines = [
                            head,
                            `Your key: ${FINGERPRINT_RE.test(own) ? `\`${own}\`` : "**not selected**"}`,
                            ...conv.recipientIds.map(memberLine),
                            policy.sendBlocked
                                ? `Encryption: **ON, but not possible** (${policy.sendBlocked}). Messages are **not sent** until that is fixed or you run \`/pgp off\`.`
                                : `Encryption: **${policy.encrypt ? "ON" : "OFF"}**${policy.encryptBlocked ? ` (unavailable: ${policy.encryptBlocked})` : ""}`,
                            `Signing: **${policy.sign ? "ON" : "OFF"}**${policy.signExplicit ? "" : " (default)"}${policy.encrypt ? " (inside the encrypted block)" : " (clearsigned)"}`,
                            `Send hook: ${checkSendHook()}`,
                        ];
                        return reply(lines.join("\n"));
                    }
                    case "settings": {
                        if (!conv) return reply(notDm);
                        openConversationSettings(channel.id);
                        return;
                    }
                    case "on":
                    case "off": {
                        if (!policy || !conv || !keys) return reply(notDm);
                        if (sub === "on" && policy.encryptBlocked) {
                            return reply(`Encryption is not possible: ${policy.encryptBlocked}. Click the lock in the chat bar to ${conv.kind === "guild" ? "choose recipients" : "manage keys"}.`);
                        }
                        if (sub === "on" && !FINGERPRINT_RE.test(own)) return reply("No own key selected. Open Settings → Plugins → DiscordPG.");
                        await setEncrypt(channel.id, sub === "on");
                        return reply(`Encryption is now **${sub.toUpperCase()}** for this ${conv.kind === "dm" ? "DM" : conv.kind === "group" ? "group" : "channel"}.`);
                    }
                    case "sign": {
                        if (!conv) return reply(notDm);
                        const state = findOption(subOpts, "state", "default");
                        await setSign(channel.id, state === "default" ? undefined : state === "on");
                        const p = policyFor(channel.id)!;
                        return reply(`Signing is now **${p.sign ? "ON" : "OFF"}**${state === "default" ? " (default)" : ""}${p.encrypt ? "" : " (clearsigned)"}.`);
                    }
                    case "fingerprint": {
                        if (!conv) return reply(notDm);
                        if (conv.kind === "dm") openFingerprintModal(conv.recipientIds[0], userName(conv.recipientIds[0]));
                        else if (conv.recipientIds.length) openGroupKeysModal(conv.recipientIds);
                        else openConversationSettings(channel.id);
                        return;
                    }
                    case "lock": {
                        await lockNow(true);
                        return;
                    }
                    default:
                        return reply("Unknown subcommand.");
                }
            },
        },
    ],
});

// Exposed for debugging from the console: Vencord.Plugins.plugins.DiscordPG.debug
export const debug = { getRecord, showToast };
