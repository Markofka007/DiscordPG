# DiscordPG — Discord Privacy Guard

GnuPG end-to-end encryption and signing for Discord **DMs, group DMs and server channels**, plus encrypted attachments, as a [Vencord](https://vencord.dev) user plugin. Outgoing messages are encrypted (and signed) for the recipient with your GnuPG key; incoming PGP messages are decrypted and rendered in place with a signature verdict, a lock indicator and a "show original" toggle.

The name is a play on GnuPG. This is a security-focused tool: see [SECURITY.md](SECURITY.md) for what this does and does not protect, and the design principles everything follows.

This is a vibecoded personal project that I made for fun. DiscordPG has not been thoroughly QA tested at scale for all edge cases. Assume that there are flaws.

## How it works

```
Discord renderer (Vencord plugin, untrusted)       Electron main process (native/, trusted)
  pre-send hook  ──encrypt request──▶  typed IPC  ──▶  gpg --encrypt --sign   ──▶ gpg-agent / scdaemon / YubiKey
  message render ◀──plaintext+verdict─  validated  ◀──  gpg --decrypt
```

* Your private key never enters Discord's process. All private-key operations happen in gpg-agent (and your smartcard, if you use one). PIN entry goes through pinentry, not Discord.
* Messages are standard ASCII-armored OpenPGP, so any PGP tool can read them. On the wire they are wrapped in a code block so people without the plugin see a tidy monospace block.
* Messages are encrypted to every member of the conversation **and to you**, and signed by default. In a group DM every member must have a bound key; otherwise nothing is encrypted (and the lock says why). In a server channel *you* pick the recipients (bound contacts) from the lock icon; everyone else sees ciphertext.
* **Signing is a per-conversation switch.** It is on by default when encryption is on (the signature rides inside the encrypted block). With encryption off you can still sign: messages go out *clearsigned* (a readable text block with the signature underneath, which anyone can read and OpenPGP users can verify). Sign-only mode is gated by a once-per-session OS dialog; see SECURITY.md.
* **Attachments** get a lock of their own on each file card in the composer (off by default, see `encryptAttachmentsByDefault`). Locked files go out as binary `name.ext.gpg`; recipients get *Preview* (images) or *Decrypt & save…* (a system save dialog; the bytes never pass through Discord's renderer). Discord normally starts uploading a file the moment it is added; in conversations DiscordPG manages the upload is held back until the send, so locked files are encrypted before any byte leaves your machine. Downloads happen in the main process too, and only from Discord's attachment CDN. Small `.asc` and `message.txt` files are inspected on sight, so a public key that Discord turned into a file still gets its *Import key* banner.
* Who-owns-which-key ("bindings") is stored by the main process in a file only your user can read, and every change is confirmed in an OS dialog that the renderer cannot spoof or auto-click.
* **Fail closed.** If encryption is on and anything fails (gpg error, missing key, oversize, missing send hook), the message is not sent. There is no silent plaintext fallback.

## Requirements

* Linux/macOS/Windows desktop Discord (or Vesktop) with Vencord. Not the web build.
* GnuPG 2.2+ with a running gpg-agent. Tested with GnuPG 2.4.4 + keyboxd and a YubiKey 5 on Linux. On Windows use [Gpg4win](https://gpg4win.org/) installed under *Program Files* (see [Windows notes](#windows-notes)).
* An OpenPGP key with an encryption-capable subkey. **Use ECC (ed25519/cv25519).** RSA-4096 recipients produce ciphertext too large for Discord's 2000-character limit.

## Install

Vencord has no way to load a plugin into an already-installed copy: every plugin is compiled into Vencord when Vencord is built, and half of DiscordPG runs in Discord's main process, which makes that doubly true. So there are two ways to get it:

| | Add DiscordPG to your Vencord (recommended) | Standalone bundle |
|---|---|---|
| What you get | Your own Vencord build with DiscordPG as one more plugin | A prebuilt Vencord with DiscordPG inside |
| Your Vencord version, updater and own plugins | Kept | Replaced by the bundle's build (settings kept) |
| You need | Git, Node.js 18+, pnpm | Nothing but GnuPG |
| You run | Code you can read, built on your machine | A signed binary bundle from the Releases page |

Both need GnuPG set up first (see [Requirements](#requirements)).

### Add DiscordPG to your Vencord (recommended)

This works with the Vencord source checkout you already build from, or with a new one. If you currently use the Vencord you got from the official installer, this switches Discord to a build made on your machine; your Vencord settings carry over, Vencord's updater keeps working, and running the official installer again takes you back.

**With the setup script.** From a clone of this repository:

```sh
git clone https://github.com/Markofka007/DiscordPG
DiscordPG/scripts/setup.sh --vencord /path/to/your/Vencord    # Linux / macOS
```

```powershell
powershell -ExecutionPolicy Bypass -File DiscordPG\scripts\setup.ps1 -Vencord C:\path\to\Vencord   # Windows
```

Leave out `--vencord` and the script offers to clone Vencord into `~/Vencord`. It checks for Git, Node.js and pnpm, puts DiscordPG into `src/userplugins/discordPG.desktop`, runs `pnpm install --frozen-lockfile` and `pnpm build`, checks that DiscordPG really is in the build, and then runs Vencord's installer to point Discord at it. The only thing it adds to your checkout is that one folder: it does not pull, reset or edit Vencord, and it does not touch your other plugins. Options: `--no-inject` (build only), `--branch stable|ptb|canary`, `--location <Discord dir>`, `--yes`.

**By hand.** The same steps, if you prefer to run them yourself:

```sh
git clone https://github.com/Vendicated/Vencord        # skip if you already have a checkout
cd Vencord
git clone https://github.com/Markofka007/DiscordPG src/userplugins/discordPG.desktop
pnpm install --frozen-lockfile
pnpm build
pnpm inject            # pick your Discord install; quit Discord first
```

The folder must be named `discordPG.desktop`; the suffix tells Vencord's build that the plugin is desktop-only.

Then fully restart Discord and open **Settings → Vencord → Plugins → DiscordPG**: check that it is enabled and pick your key in the panel at the top of its settings page.

* **Updating DiscordPG:** `git pull` inside `src/userplugins/discordPG.desktop`, `pnpm build`, then quit and restart Discord (Ctrl+R is not enough: the main-process half only reloads on a full restart, and the plugin shows a notice when the two halves are out of sync).
* **Updating Vencord:** as you do now (`git pull` and `pnpm build`, or Vencord's in-app updater). `src/userplugins` is ignored by Vencord's repository, so updates leave DiscordPG in place.
* **After Discord updates itself** the patch is gone (it lives in the `app-<version>` folder): run `pnpm inject` again.
* **Removing DiscordPG:** delete `src/userplugins/discordPG.desktop` and run `pnpm build`. `pnpm uninject` removes Vencord from Discord altogether.

Tested with Vencord 1.15.17 (`d07030c`), Discord stable on Linux, GnuPG 2.4.4. If the build fails on an older Vencord checkout, update Vencord first.

#### Other plugins in the same build

DiscordPG is made to coexist with any other plugins you compile in, with three things to know:

* Every plugin runs inside Discord's renderer and can read whatever you can read there, decrypted messages included. DiscordPG is only as private as the other plugins you choose to build with it (see [SECURITY.md](SECURITY.md), "Plaintext inside the renderer").
* Plugins that rewrite outgoing messages use the same pre-send hook as DiscordPG, and Vencord runs those hooks in plugin start order, which you do not control. A plugin that runs after DiscordPG edits the ciphertext, so the message arrives unreadable; nothing leaks. A plugin that runs before it has its changes encrypted along with the rest.
* If another plugin patches the same piece of Discord's code, a DiscordPG patch can fail to apply. The upload hold and the send-hook check then refuse to send rather than send in the clear.

Forks of Vencord that keep the `src/userplugins` convention may work but are not tested.

### Standalone bundle

For people who do not want a build toolchain: each release on the [Releases page](https://github.com/Markofka007/DiscordPG/releases) has a zip with a complete Vencord build that includes DiscordPG, plus `install.ps1` / `install.sh`. Unzip it and run the script for your OS; `INSTALL.md` inside the zip walks through GnuPG setup, verifying the zip's signature, upgrading and uninstalling.

Know what it does before you run it: Discord will load the bundle's Vencord build **instead of** any Vencord you already have. Your Vencord settings are kept, but plugins you added yourself are not in that build, and Vencord's updater is switched off in it (otherwise it would replace the bundle with an upstream build that has no DiscordPG), so you update by installing a newer bundle. If the installer finds an existing Vencord it explains this and asks before changing anything.

### Windows notes

* gpg is located via `gpgconf`, the Gpg4win registry key, and the default *Program Files* locations. It must live under *Program Files* or the Windows directory; a `gpg.exe` in a user-writable place (scoop, a portable copy, Downloads) is refused, including through the `gpgPath` setting. The reason is shown in the settings panel when gpg is not found.
* PIN entry uses Gpg4win's pinentry (a normal window). YubiKeys work through Gpg4win's scdaemon.
* The bindings file lives at `%APPDATA%\Vencord\discordpg\bindings.json`. Windows has no 0600 mode; the file is protected by your profile's ACL instead.
* Discord's self-updates on Windows land in a new `app-<version>` folder and drop the patch; run `pnpm inject` (or the bundle's install script) again afterwards.

## Using it

1. **Share keys.** In a DM, run `/pgp share` (posts your public key) or right-click the lock in the chat bar → *Copy my public key*. When a contact posts theirs, an **Import key for @user** button appears under their message (also for small `.asc` attachments). Confirm in the system dialog.
2. **Verify.** Right-click the lock → *View / verify fingerprints*. Read the fingerprints to each other over a call or in person, then *Mark as verified*. Verified signers get a green lock.
3. **Chat.** With a key bound, encryption turns on for that DM (configurable). **Click the lock in the chat bar** to open the conversation settings: *Encrypt messages*, *Sign messages*, and (server channels) the recipient list. Right-click the lock for quick toggles; `/pgp status`, `/pgp on|off`, `/pgp sign on|off|default` do the same. **Group DMs:** encryption is only possible once every member has a bound key (the settings box shows who is missing); messages are encrypted to all members. **Server channels:** pick recipients among your bound contacts, then switch *Encrypt* on. Encryption is never on by default in a server; signing-only is available in every kind of channel.
4. **Attachments.** Each file card in the composer gets a lock. Locked files are encrypted to the same recipients as the text and uploaded as `name.ext.gpg`. If the text is encrypted but a file is not, you are asked once (with a *Don't ask again* box). Received `.gpg`/`.pgp`/`.asc` files show *Preview* (images) and *Decrypt & save…* buttons; unsigned or wrongly-signed files get an OS warning before saving.
5. **Read.** Incoming PGP messages decrypt (or verify) automatically, or on click (see `autoDecrypt`), with a footer showing *Encrypted* or *Signed* plus the signature verdict and a **Show original** link. Unsigned or wrongly-signed messages are hidden behind a warning by default (`requireSignatures`), and a sign-only message whose signature was made for another channel is flagged as a probable copy.
6. **Lock.** `/pgp lock` or the chat-bar menu forgets all decrypted text (and attachment previews) and tells gpg-agent to drop cached PINs. This also happens automatically after `autoLockMinutes` of inactivity, and it re-arms the sign-only session dialog.

### YubiKey touch policy

Each decryption and signature touches the card. With touch policy `on` you would tap once per message; `cached` requires a tap but then allows further operations for 15 seconds, which makes scrolling through an encrypted conversation bearable:

```sh
ykman openpgp keys set-touch dec cached
ykman openpgp keys set-touch sig cached   # or "on"
```

### Limitations

* Server channels: only the recipients you picked can read an encrypted message; everyone else (with or without the plugin) sees ciphertext. Voice channels and forum containers are out of scope.
* Stickers and reactions are not encrypted. Unlocked attachments go out as they are (after a prompt).
* Attachments are capped at 64 MiB in and out; image previews at 32 MiB. Discord's own upload limit applies to the encrypted file (same size as the original plus a few bytes).
* Mentions inside encrypted text render but do not notify.
* Ciphertext is what Discord's servers, mobile clients, search, notifications and reply previews see.
* Roughly 1200 characters of plaintext fit under the 2000-character limit with ECC keys (4000 with Nitro). Longer messages are refused rather than split.

## Development

Work in the plugin folder inside a Vencord checkout (`src/userplugins/discordPG.desktop`, as in the install steps), or keep this repository next to Vencord and symlink it there.

```sh
pnpm install
pnpm test          # unit tests + integration tests against a throwaway GNUPGHOME (needs gpg)
pnpm tsc -p tsconfig.test.json
```

Iterating: `pnpm build --watch` in the Vencord checkout, then `Ctrl+R` in Discord. Changes under `native/` run in Discord's main process, which Ctrl+R does not reload: fully quit and restart Discord for those.

`tsconfig.json` is deliberately not in the repository. Inside a Vencord tree the build and your editor use Vencord's own `tsconfig.json`, so none is needed. With the symlink layout, esbuild resolves the real path and looks for a `tsconfig.json` there, so create a local one (it is git-ignored) that points at your Vencord checkout, or the build cannot resolve Vencord's `@api/...` imports:

```json
{ "extends": "../Vencord/tsconfig.json", "include": ["**/*.ts", "**/*.tsx"], "exclude": ["node_modules", "dist"] }
```

Building the standalone bundle for a release:

```sh
pnpm package                      # builds the Vencord checkout with --standalone --disable-updater, zips release/
pnpm package --sign <FINGERPRINT> # same, plus a detached .asc signature
```

The bundle is platform-independent (built "standalone", so no `process.platform` is baked in). `pnpm package` leaves the Vencord checkout's `dist/` as that standalone build; run a plain `pnpm build` there afterwards to get your normal dev build back.

Layout:

| Path | Role |
|---|---|
| `core/` | Pure TypeScript shared by both sides: types, wire format, renderer-side backend wrapper, send path, hook check |
| `native/` | Electron main process: typed IPC surface, validators, gpg runner, status/colon parsers, binding store, OS dialogs |
| `store/` | Renderer state: decrypt cache (RAM only), channel prefs, binding cache, auto-lock |
| `components/` | React UI: accessory, lock decoration, chat-bar button, modals, settings panel |
| `tests/` | vitest suites and captured gpg fixtures |

License: GPL-3.0-or-later (same as Vencord).

## Advisories

* **0.2.3 and earlier: wrong-key encryption, private-key import and plaintext fallback.** A crafted key in your keyring could make messages for a contact be encrypted to someone else; a private key disguised as a public key block was imported despite the error shown; and a conversation whose encryption became impossible (e.g. a member without a key joined a group DM) silently sent the next message unencrypted. Fixed in 0.2.4. What to check in your keyring is described under Advisories in [SECURITY.md](SECURITY.md).

* **0.2.0 and 0.2.1: locked attachments were sent unencrypted.** Discord uploads a file the moment it is added to the composer; those versions only swapped the bytes at send time, so the message referenced the already-uploaded original under a `.gpg` name. If you sent locked files with either version, delete those messages: the content is readable by Discord and anyone in the conversation. Fixed in 0.2.2, which holds uploads back in managed conversations until they are encrypted and refuses to send a locked file that Discord uploaded early.