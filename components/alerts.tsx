/*
 * DiscordPG (Discord Privacy Guard) - GnuPG encryption for Discord DMs, as a Vencord plugin
 * Copyright (c) 2026 DiscordPG contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { FormSwitch } from "@components/FormSwitch";
import { Paragraph } from "@components/Paragraph";
import { Alerts, useState } from "@webpack/common";

import { settings } from "../settings";

/**
 * "Encryption is on, but these files are not encrypted." Resolves true to send anyway. Ticking
 * "Don't ask again" clears the warnUnencryptedAttachments setting when the user confirms.
 */
export function confirmUnencryptedFiles(names: string[]): Promise<boolean> {
    let dontAsk = false;
    const Body = () => {
        const [v, setV] = useState(false);
        return (
            <>
                <Paragraph>
                    Your message text will be encrypted, but {names.length === 1 ? "this file" : "these files"} will be uploaded as-is,
                    readable by Discord and by everyone in the conversation:
                </Paragraph>
                <ul className="vc-pg-filelist">{names.map(n => <li key={n}><code>{n}</code></li>)}</ul>
                <Paragraph className="vc-pg-muted">To encrypt a file, click the lock on its card above the message box.</Paragraph>
                <FormSwitch title="Don't ask again" value={v} onChange={x => { setV(x); dontAsk = x; }} hideBorder />
            </>
        );
    };
    return new Promise<boolean>(resolve => {
        let done = false;
        const finish = (send: boolean) => {
            if (done) return;
            done = true;
            if (send && dontAsk) settings.store.warnUnencryptedAttachments = false;
            resolve(send);
        };
        Alerts.show({
            title: "Send unencrypted attachments?",
            body: <Body />,
            confirmText: "Send anyway",
            cancelText: "Cancel",
            onConfirm: () => finish(true),
            onCancel: () => finish(false),
            onCloseCallback: () => finish(false),
        });
    });
}
