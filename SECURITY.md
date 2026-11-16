# Disclaimer

This is a vibecoded personal project that I made for fun. DiscordPG has not been thoroughly QA tested at scale for all edge cases. Assume that there are flaws.

# Security

DiscordPG is a security tool, so this document is part of the product. If anything here does not match the code then don't trust the code. If anything here does not match the code of an official release, notify me immediately at marko@dread-sec.com.

## Threat model

**Protected**

* **Message content** from Discord's servers, logs, moderation tooling, data requests, and anyone who does not hold the recipient's private key. Only standard OpenPGP (AES/OCB or MDC, ECDH or RSA as the keys dictate) leaves the client.
* **Your private key.** It never enters the Discord process. gpg is spawned from the Electron main process and talks to gpg-agent; with a smartcard the key never leaves the card.
* **Your PIN/passphrase.** Entered through pinentry, never through a Discord UI.
* **Key bindings** (which fingerprint belongs to which Discord user) against tampering by other code in the renderer. They live in a 0600 file owned by the main process and every change requires a native `dialog.showMessageBox` confirmation showing the user tag and full fingerprint. (On Windows the file is protected by the profile ACL rather than a 0600 mode.)
* **Silent downgrade to plaintext.** If encryption is on for a conversation and anything fails, the message is not sent. In a group DM, one member without a bound key makes encryption unavailable for the whole group; a message is never sent readable by some members and not others. "Unavailable" does not mean "send it in the clear": once a conversation is committed to encryption (you switched it on, or a message already went out encrypted there), text is refused while encryption is impossible, e.g. after someone without a key joins the group, a binding is forgotten, or the bindings could not be loaded, until that is fixed or you turn encryption off for that conversation yourself. Only a conversation that was never encrypted (the ordinary DM with someone who has no key) sends plaintext without asking. The plugin also verifies that Vencord's pre-send and pre-edit hooks were actually injected into Discord's code: it registers "witness" patches on the same modules that only match the injected `_handlePreSend` / `_handlePreEdit` calls. If a module has run without the witness firing, the plugin disables sending (and plaintext edit prefill) loudly instead of guessing.
* **Key substitution inside the keyring.** gpg matches a fingerprint against subkeys as well as primary keys, and anyone can publish a key that carries *your contact's* primary key as one of its own subkeys. With such a key in the keyring, "encrypt to Bob's fingerprint" can resolve to the impostor's key. DiscordPG therefore requires, when binding and again before every encrypt, export and signature, that each fingerprint resolves to exactly one key and is that key's primary fingerprint, and afterwards rejects gpg's output if gpg reports having used any key other than the requested ones (`ambiguous-key`). Nothing is sent in that case; remove the impostor with `gpg --delete-keys`.
* **Secret keys smuggled in as public keys.** gpg imports by packet type and ignores the armor label, so a "PUBLIC KEY BLOCK" can carry a secret key that would then count as one of *your* keys. Every import is dry-run first (`--import-options show-only`) and refused if it contains any secret key material; nothing reaches the keyring.
* **Signing oracle abuse (encrypted mode).** Encryption signs only *inside* the encrypt operation, and only to recipients that are your own keys or user-confirmed bindings. Hostile renderer code cannot obtain an encrypted-and-signed message that anyone but a trusted contact could read.
* **Signing oracle abuse (sign-only mode), bounded rather than eliminated.** Signing without encryption (clearsign) *is* a signing oracle for any code in the renderer: it can obtain a real signature from your key over text of its choosing. It is off by default per conversation, and the main process enforces, independently of the renderer: a once-per-session OS dialog before the first such signature (re-armed by lock/restart), a rate limit (10 per minute), text-mode signatures only, at most 4000 characters of printable text, and a `channel@discordpg.invalid` notation naming the Discord channel in every signature. That notation lets DiscordPG flag a signed message copied into another channel, and lets a human reviewer recognise a Discord chat signature for what it is. It does not stop a determined verifier from accepting such a signature over other short text, so set the YubiKey `sig` touch policy to `on` if you enable sign-only mode.
* **Encrypted attachments** use the same recipient rules as text. Decrypting to disk goes through an OS save dialog in the main process; the plaintext bytes never enter Discord's renderer. Image *previews* are the exception: those bytes are handed to the renderer by explicit request, with the same exposure as decrypted text. Save names chosen by the sender are reduced to a sanitised basename. Discord uploads files as soon as they are added to the composer, before any pre-send hook runs; DiscordPG patches `CloudUpload.upload()` to hold uploads in managed conversations until the hook has encrypted or deliberately released them, and the hook refuses to send a locked file whose upload already started (or when that patch did not apply to the running Discord build). A plain, unlocked file is uploaded by Discord as usual, which is what "unlocked" means. The main process also performs the download: the renderer only names the attachment URL, which must be https, on one of Discord's attachment CDN hosts and under `/attachments/`, with redirects refused, cookies omitted and a byte cap enforced while streaming, so a hostile renderer cannot turn this into a request to localhost, the LAN or an arbitrary site.
* **Decompression bombs / runaway output**: `gpg --max-output`, hard caps on IPC payloads (64 KiB armor; 64 MiB attachments), stdout/stderr caps on the child process, and a per-operation timeout.
* **Arbitrary binary execution via the `gpgPath` setting.** A custom path must be absolute, be named `gpg`/`gpg2`, exist, and sit in a directory the current user cannot write to. On Windows, where `fs.access(W_OK)` cannot see ACLs, the rule is instead that it must sit under *Program Files* or the Windows directory (admin-protected by default); per-user installs are refused.

**Not protected**

* **Metadata.** Who talks to whom, when, how often, and roughly how long each message is.
* **Unlocked attachments, stickers, reactions, typing indicators, read states.** An attachment whose lock is off is uploaded in the clear even next to encrypted text; the composer shows the lock state per file and asks once before such a send (the prompt can be silenced).
* **Server-channel recipient lists** live in renderer storage. Hostile renderer code could add a recipient, but only among contacts whose keys you have already bound, because the main process refuses any other fingerprint.
* **Plaintext inside the renderer.** Anything with code execution in Discord's renderer (another plugin, a compromised Discord build, an XSS) can read what you read and type, and can ask the IPC bridge to decrypt messages while the card is unlocked. The YubiKey touch policy and the idle auto-lock bound this; they do not eliminate it.
* **Forward secrecy.** OpenPGP has none. Compromise of a private key exposes all past traffic encrypted to it. Rotate keys if you need to limit that window.
* **Availability on other clients.** Mobile, web, search, notifications and reply previews show ciphertext.
* **Discord's Terms of Service.** Client modifications violate them.

## Design principles the code follows

1. Key material never enters Discord. Secret-key export is not implemented anywhere.
2. Fail closed on the send path.
3. The IPC surface is minimal, typed, and validates every argument (`native/schema.ts`). No raw gpg arguments cross the boundary.
4. Trust decisions (bind, rebind, verify, forget) happen in native dialogs.
5. Plaintext lives in memory only, for this session. There is no persistent plaintext cache. `lock` clears it and asks gpg-agent to drop cached PINs.
6. gpg is invoked with `--batch --no-tty --status-fd 2 --exit-on-status-write-error --no-auto-key-retrieve --no-auto-key-locate --disable-dirmngr --max-output 1048576`, recipients by full fingerprint, and `--trust-model always` (trust is the user's confirmed binding, not gpg ownertrust).
7. Every decrypted or verified message carries a verdict computed on the trusted side: `self`, `verified`, `unverified-contact`, `mismatch`, `unknown-signer`, `unsigned`, `bad`, plus a channel-mismatch flag for sign-only messages. An encrypted message is a success only if gpg reports `DECRYPTION_OKAY`, reports no `NODATA`/`FAILURE`/`BADSIG`, and carries at most one signature; a sign-only block must carry exactly one signature and must not be encrypted (the `verify` IPC refuses encrypted input so it cannot double as a decrypt path).
8. Three Discord-internals patches (hiding the ciphertext row; the per-file lock on upload cards, at the same anchor Vencord's own AnonymiseFileNames uses; holding back uploads until the send hook has encrypted them); everything else uses public Vencord APIs. Zero runtime npm dependencies. Decrypted markdown is rendered by Discord's own parser.
9. Full 40-hex fingerprints only. Never 8- or 16-hex key IDs in UI or storage.
10. Nothing logs plaintext, armor or fingerprints at info level.

## What you are trusting when you install it

* **Source install** (DiscordPG cloned into your own Vencord checkout): you run the code in this repository, built on your machine, next to whatever Vencord commit and other plugins you chose. Release tags are signed; `git verify-tag vX.Y.Z` checks that a checkout is what was released. Other plugins in the same build share Discord's renderer with DiscordPG, so they are inside the trust boundary described under "Plaintext inside the renderer" above.
* **Standalone bundle**: a prebuilt, minified Vencord build that runs in Discord's renderer *and* main process. You cannot meaningfully review it, so you are trusting whoever built it. Each release zip has a detached signature (`.zip.asc`); verify it with `gpg --verify` against the maintainer's key before running the install script, and get that key's fingerprint from somewhere other than the download page. `VERSION.json` in the zip records the DiscordPG and Vencord commits it was built from.
* Both install scripts download Vencord's official command-line installer from GitHub at run time (the same binary `pnpm inject` uses). It is not pinned or verified by DiscordPG.

## Reporting

Please report vulnerabilities privately to the maintainer rather than in a public issue. Include
the Vencord commit, Discord build, GnuPG version and reproduction steps. Do not include message
content or private keys.

## Advisories

* **0.2.3 and earlier: three issues found in a code audit, fixed in 0.2.4.**
1. *Encryption to the wrong key.* A key in your keyring that carried a contact's primary key as a subkey could make messages "to" that contact be encrypted to the other key's owner instead (which key wins depends on gpg's keyring backend and import order). If you ever imported a key from someone you do not trust, run `gpg --list-keys --with-subkey-fingerprint` and look for a subkey fingerprint that equals a contact's primary fingerprint.
2. *Private key accepted as a public key.* Importing a block labelled as a public key that actually held a private key showed an error but still put that key pair into your keyring, where it counted as one of your own keys. Check `gpg --list-secret-keys` for keys that are not yours and delete them (`gpg --delete-secret-and-public-keys <fingerprint>`).
3. *Silent fallback to plaintext.* When encryption became impossible in a conversation that had it on (a member without a key joined a group DM, bindings failed to load, a message was sent in the first moments after startup), the next message was sent unencrypted with only the lock icon changing.

* **0.2.0 and 0.2.1: locked attachments were sent unencrypted.** Discord uploads a file the moment it is added to the composer; those versions only swapped the bytes at send time, so the message referenced the already-uploaded original under a `.gpg` name. If you sent locked files with either version, delete those messages: the content is readable by Discord and anyone in the conversation. Fixed in 0.2.2, which holds uploads back in managed conversations until they are encrypted and refuses to send a locked file that Discord uploaded early.