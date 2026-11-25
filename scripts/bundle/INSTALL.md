# Installing the DiscordPG standalone bundle

This folder is a complete build of [Vencord](https://vencord.dev) with the DiscordPG plugin
compiled in. Discord can only load one Vencord build at a time, so installing this one makes Discord
load it **instead of** any Vencord you already have. Your Vencord settings are kept; plugins you
added to Vencord yourself are not part of this build. Vencord's updater is disabled in it (otherwise
it would swap the bundle for an upstream build without DiscordPG), so you get updates by installing a
newer bundle.

**Already build Vencord from source, or have your own plugins?** Do not use this bundle. Add DiscordPG
to your own checkout instead and keep everything: see "Add DiscordPG to your Vencord" in the README at
<https://github.com/Markofka007/DiscordPG>. If the install script finds an existing Vencord it explains the
above and asks before it changes anything.

## 1. Install GnuPG

**Windows:** install [Gpg4win](https://gpg4win.org/) (or the plain GnuPG installer) with the
default location under *Program Files*. DiscordPG refuses to run a `gpg.exe` from a per-user
directory (scoop, portable copies) because anything in your profile could be swapped by other
software. Kleopatra (part of Gpg4win) is the easiest way to create or import your key.

If you need help using Kleopatra or creating a new PGP key you can folow my guide [here](https://dread-sec.com/pgp).

**Linux:** `gpg` from your distribution. **macOS:** [GPG Suite](https://gpgtools.org/) or Homebrew `gnupg`.

Check in a terminal / PowerShell:

```
gpg --version
gpg --list-secret-keys
```

You need a key with an **encryption-capable subkey**. Prefer ECC (ed25519 / cv25519): RSA keys
produce ciphertext that often exceeds Discord's 2000-character limit. If you have none:

```
gpg --quick-gen-key "Your Name <you@example.org>" ed25519 cert never
gpg --quick-add-key <FINGERPRINT> cv25519 encr never
gpg --quick-add-key <FINGERPRINT> ed25519 sign never
```

YubiKey users: Gpg4win's scdaemon talks to the card; `gpg --card-status` should list it.

## 2. Verify the bundle (optional but recommended)

If you got a `.zip.asc` next to the zip, and you have the author's public key:

```
gpg --verify DiscordPG-*.zip.asc DiscordPG-*.zip
```

## 3. Install

Close Discord first.

**Windows:** right-click the zip → *Extract All*, open the extracted folder, then in PowerShell
(Shift+right-click in the folder → *Open PowerShell window here*):

```
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

The installer prints `INFO Patching C:\Users\<you>\AppData\Local\Discord...` and
`Successfully patched`; the script then prints *Done*.

**Linux / macOS:**

```
./install.sh
```

Both scripts copy the files to a per-user folder (`%APPDATA%\DiscordPG` or `~/.config/DiscordPG`),
download the official Vencord command-line installer from GitHub, and run it in "dev install"
mode pointing at that folder. Options: `-Branch ptb` / `--branch canary`, `-Location <dir>` /
`--location <dir>` to pick a specific Discord install, `-Yes` / `--yes` to skip the question asked
when you already use Vencord, `-Uninstall` / `--uninstall` to remove.

## 4. First run

1. Start Discord. Open **Settings → Vencord → Plugins** and confirm **DiscordPG** is on
   (it is enabled by default in this build).
2. Open the DiscordPG settings page. The status table shows the gpg it found. If it says
   *not found*, the reason is printed next to it.
3. Pick **Your key**.
4. In a DM, run `/pgp share` to post your public key; when your contact posts theirs, click
   **Import key** under their message and confirm in the system dialog.
5. Compare fingerprints out of band (right-click the lock → *View / verify fingerprints*), then
   mark the key verified.

## Upgrading to a newer bundle

Run the installer from the new bundle exactly like the first time. It stops Discord first; that
matters, because half of DiscordPG runs in Discord's main process, which only reloads on a full
restart (Ctrl+R is not enough). If you ever see "Discord's main process is running a different
DiscordPG build", fully quit Discord (tray icon → Quit) and start it again.

**Upgrading from 0.2.0 or 0.2.1:** encrypted attachments sent with those versions were uploaded
unencrypted under a `.gpg` name (see the Advisories section of the README). Delete such messages.

## After Discord updates itself

Discord installs each update into a new `app-<version>` folder, which drops the patch. Run the
install script again (same bundle), then restart Discord.

## Going back to the Vencord you had before

Your previous Vencord was not deleted; Discord just stopped loading it. To switch back without
removing Vencord:

* **Official Vencord:** run the official installer from <https://vencord.dev/download>, pick your
  Discord install and click **Install** (or **Repair**).
* **Your own source build:** quit Discord and run `pnpm inject` in your Vencord checkout.

Your settings are shared between builds, so nothing else needs doing. DiscordPG's messages show as
plain `-----BEGIN PGP MESSAGE-----` blocks again unless your own build includes DiscordPG.

## Uninstalling (removing Vencord and DiscordPG completely)

Nothing here is permanent. Removing it puts Discord back to a stock install, and your Discord
account, messages and GnuPG keys are not affected.

### 1. Unpatch Discord

Quit Discord fully first (tray icon → *Quit Discord*), then use either method.

**With the bundle's script** (from the folder you unzipped):

```
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Uninstall     # Windows
./install.sh --uninstall                                              # Linux / macOS
```

Add `-Branch ptb` / `--branch canary` or `-Location <dir>` / `--location <dir>` if you used them
when installing. The installer should end with `Successfully unpatched`.

**Without the bundle** (you already deleted it): download the official Vencord installer from
<https://vencord.dev/download>, run it, pick your Discord install and click **Uninstall**.

Start Discord again. The **Vencord** section is gone from Settings and encrypted messages show as
plain `-----BEGIN PGP MESSAGE-----` blocks: that means it is removed.

If neither method works, reinstalling Discord from <https://discord.com/download> also removes the
patch. So does a Discord update, which is why the patch has to be re-applied after one.

### 2. Delete the leftover files (optional)

Unpatching leaves a few small folders in your profile. Delete them if you do not plan to come back:

| What | Windows | Linux | macOS |
| --- | --- | --- | --- |
| This build's files and the downloaded installer | `%APPDATA%\DiscordPG` | `~/.config/DiscordPG` | `~/Library/Application Support/DiscordPG` |
| Vencord settings and DiscordPG's key-binding list (`discordpg/bindings.json`) | `%APPDATA%\Vencord` | `~/.config/Vencord` | `~/Library/Application Support/Vencord` |

On Windows, paste the path into the Explorer address bar to open it. If you used Vencord before
this build and want to keep using it, keep the `Vencord` folder and delete only `discordpg` inside it.

DiscordPG never stores plaintext or private keys, so there is nothing else to clean up in Discord.

### 3. GnuPG (optional)

Your own keys stay in GnuPG and keep working everywhere else. The public keys you imported for
contacts are also still in your keyring; remove one with `gpg --delete-key <fingerprint>` (or in
Kleopatra: right-click the certificate → *Delete*). Gpg4win itself is uninstalled like any other
program, from *Settings → Apps*.

Messages you sent or received while testing stay encrypted in Discord. You can still read them
later by copying a block into Kleopatra's Notepad (or `gpg --decrypt`), as long as you keep your key.
