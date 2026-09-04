# photo2seed

**GitHub: https://github.com/kccleoc/photo2seed**

Derive a **BIP39 seed from photo entropy mixed with OS CSPRNG**, then seal it in
a **Krux KEF** (Krux Encrypted Format) envelope and render it as a **base43 QR
code** that Krux can scan, decrypt, and load. A master-key fingerprint (XFP)
can be shown to verify the seed on any wallet.

KEF envelope layout, v20 (AES-GCM) parameters, PBKDF2 iteration encoding, and
the base43 alphabet match the Krux reference implementation
([`src/krux/kef.py`](https://github.com/selfcustody/krux/blob/develop/src/krux/kef.py),
[`baseconv.py`](https://github.com/selfcustody/krux/blob/develop/src/krux/baseconv.py))
and the [KEF spec](https://github.com/selfcustody/krux/blob/develop/docs/getting-started/features/encryption/kef-specifications.en.md).

**KEF (v20 AES-GCM QR) output is always the default.**

## Install

Run from a clone or installed as a command:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
./photo2seed.py install     # adds 'photo2seed' to ~/.local/bin (on PATH)
photo2seed uninstall        # removes it again
```

`install` writes a small launcher that points at the live source, so updates
are picked up automatically. Or build a **single self-contained binary** — see
[Single binary / Tails OS](#single-binary--tails-os).

## Usage

```bash
photo2seed PATH... [options]
photo2seed --download-random [N] [options]   # no PATH needed - fetch random photos
```

Default behavior: photos in → seed derived → **KEF password prompted** →
**KEF QR PNG written**. Seed material is **not printed** unless you pass
`--show-words`.

`PATH...` accepts one or more image files and/or directories (recursive), and
is **optional** when `--download-random` is used. The two may be combined
(your photos plus the downloaded ones all feed the entropy).

Examples:

```bash
photo2seed ~/Pictures/trip/                  # default: words -> KEF QR PNG + password
photo2seed --download-random                 # fetch 10 random photos to /tmp, then derive (standalone)
photo2seed ./myseedphoto --add-download-random 10  # mix 10 random /tmp photos with ./myseedphoto (requires PATH)
photo2seed a.jpg some/dir/ --words 24         # 24-word seed
photo2seed photos/ --show-words              # also print words/entropy/hashes
photo2seed photos/ --xfp                     # also show the master-key fingerprint
photo2seed photos/ --label "Leo Vault #1"    # label under the QR (max 20 chars)
photo2seed photos/ --lock                    # archive PASS photos to ./<word>-<word>/ read-only (PASS only, REJECT excluded)
photo2seed photos/ --lock-dir ./vault --no-mix-rng --show-words  # deterministic lock + verify (PASS only)
photo2seed ./myseedphoto --add-download-random 5 --burn  # mix 5 random, then burn /tmp/photo2seed-* after derivation
photo2seed --purge-temp --yes               # purge all temp /tmp and /var/folders photo2seed folders without confirmation
photo2seed photos/ --derive-only --xfp       # show ONLY the XFP (no words, no KEF)
photo2seed install / photo2seed uninstall    # add / remove the command
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--words 12\|24` | `12` | BIP39 mnemonic length (128 / 256-bit entropy) |
| `--download-random [N]` | off | Fetch N random [Picsum](https://picsum.photos) photos (1–10, default 10) into a fresh `/tmp` dir and use them as a photo source; requires network, mixes CSPRNG (cannot combine with `--no-mix-rng`) |
| `--id LABEL` | random per envelope | KEF envelope ID, also the PBKDF2 salt |
| `--iterations N` | `1000000` | PBKDF2-HMAC-SHA256 iterations |
| `--out FILE` | `kef_qr.png` | Output QR PNG path (refused if exists, unless `--force`) |
| `--label TEXT` | `KEF QR` | Custom text printed under the QR (max 20 chars; reject if longer) |
| `--show-words` | off | Print words, entropy, and SHA-512 digests |
| `--xfp` | off | Print the master-key fingerprint (XFP) of the derived seed |
| `--no-mix-rng` | off | Use photo entropy only (reproducible mode — see below) |
| `--derive-only` | off | Derive words only: no password, no envelope, no QR |
| `--force` | off | Overwrite an existing output QR file |
| `--lock` | off | Archive PASS photos to a new memorable two-word folder (`perch-dog`, `gaze-man`, etc.) in cwd, sealed read-only (`0444`, `uchg`/`+i` where supported) |
| `--lock-dir DIR` | off | Archive PASS photos to `DIR` (existing or new), sealed read-only; mutually exclusive with `--lock` |
| `--no-readonly` | off | With `--lock`/`--lock-dir`, keep copies writable (do not `chmod 444`) |
| `--no-manifest` | off | With `--lock`/`--lock-dir`, skip `SHA512SUMS` and `manifest.json` |
| `--add-download-random [N]` | off | Fetch N random photos (1-10, default 10) to `/tmp` and MIX with PATH photos; requires PATH; cannot combine with `--download-random` or `--no-mix-rng`; contradictory with `--burn` |
| `--burn` | off | After derivation delete the `/tmp/photo2seed-*` dir created for this run (requires `--download-random` or `--add-download-random`; mutually exclusive with `--purge-temp`) |
| `--purge-temp` / `purge` | off | Find temp folders (`photo2seed-` in `/tmp` and `/var/folders`) and offer to purge with confirmation |
| `-y` / `--yes` | off | With `--purge-temp`/`purge`, purge without confirmation (not `--force`) |
| `--min-entropy BITS` | `7.0` | Reject photos with Shannon entropy below this |
| `--min-brightness 0-255` | `30.0` | Reject photos with mean brightness below this |

## XFP (master-key fingerprint)

`--xfp` computes the BIP32 master-key fingerprint of the derived seed and
prints it as 8 uppercase hex chars, e.g. `XFP: 73C5DA0A`. It is a **public,
non-secret identifier** — the same value shown by Krux, Specter, and most
wallets — so it is printed even without `--show-words`. Use it to confirm that
a wallet/Krux holds the same seed you generated, without exposing the words.
The QR output always shows the XFP above the code (top band) so a printed
backup identifies its seed at a glance. Pair with `--derive-only` to show
nothing else:

```bash
photo2seed photos/ --derive-only --xfp
```

Derivation: mnemonic → BIP39 seed (`PBKDF2-HMAC-SHA512`, salt `mnemonic`,
2048) → BIP32 master key (`HMAC-SHA512`, key `Bitcoin seed`) → secp256k1
public key → `HASH160(pubkey)[:4]`. The vendored `ripemd160.py` (pure Python,
self-tested) is used because cryptography no longer ships RIPEMD-160.

## Pipeline

1. **Read** photos from the given paths.
2. **Shannon check** — per photo, grayscale histogram -> Shannon entropy
   `H = -Σ pᵢ·log₂pᵢ` and mean brightness. Photos that are too dark or not
   evenly distributed are **rejected** (shown by name) and skipped; the run
   continues if at least one photo passes. A warning fires when fewer than
   3 photos (or < 5 MB total) are accepted.
3. **Stop if nothing passed** — if **every** photo is rejected, seed generation
   is **stopped**: no seed is derived and no QR is written. This holds even
   with CSPRNG mixing on — photo2seed never generates a seed without at least
   one accepted photo. A clear message explains why and how to fix it.
4. **Prompt for the KEF password** (twice, via `getpass`) — before hashing, so
   a mistyped confirmation does not waste the run.
5. **SHA-512** each accepted photo (whole file, EXIF included).
6. **Order** accepted photos by filename (natural sort), tie-break by digest.
7. **Chain hash** = `SHA512( sha512(p₁) ‖ sha512(p₂) ‖ … )` over hex digests.
8. **Mix OS CSPRNG** (default): `chain = SHA512( chain ‖ os.urandom(32) )`.
   With `--no-mix-rng` this step is skipped.
9. **BIP39 entropy** = first 16 bytes (12 words) or 32 bytes (24 words).
10. **Words** — Ian Coleman method: SHA-256 checksum, 11-bit groups into the
    vendored `english.txt` (SHA-256-verified against the official BIP39 list at
    load time). Printed with BIP39 index numbers when `--show-words` is given.
11. **XFP** (optional) — BIP32 master-key fingerprint of the derived seed.
12. **KEF v20 (AES-GCM)** — plaintext is the entropy bytes; key =
    `pbkdf2_hmac_sha256(password, id, iterations)`; 12-byte random nonce; first
    4 bytes of the auth tag exposed; envelope = `len_id + id + 20 + iterations(3B)
    + nonce + ciphertext + tag`. A round-trip self-test decrypts the envelope
    before output.
13. **QR** — base43-encode the envelope, render a PNG with the seed's XFP
    printed above the code and a label below it (custom `--label` or `KEF QR`).

## Determinism — two modes

- **Default (CSPRNG mixed):** the same photos produce *different* seeds on
  every run. The **QR + password is the backup** — the photos alone are not
  sufficient to recover the seed. This is the safe default: neither a photo
  leak nor a compromised system RNG alone can reveal the seed.
- **`--no-mix-rng`:** the same unmodified photos always produce the same words
  (the KEF nonce and ciphertext differ every run). Reproducible-from-photos
  mode is only safe if the exact photo files are kept secret — see Security.

## Photo lock — read-only archive for deterministic re-derive

`--lock` / `--lock-dir` copies every **PASS** photo byte-identical into a folder, seals it read-only, and writes `SHA512SUMS` + `manifest.json` so the folder re-derives deterministically with `--no-mix-rng`.

* `--lock` creates a new memorable two-word folder in `cwd` (e.g. `perch-dog`, `gaze-man`) — `perch`/`gaze`/`calm`… + `dog`/`man`/`owl`… via `secrets.choice`. Retries 100 times to avoid collision, fallback `word-word-<nonce>`.
* `--lock-dir DIR` uses an existing or new `DIR` you choose; mutually exclusive with `--lock`.
* Sealing: `chmod 0444` + best-effort `chflags uchg` (macOS) / `chattr +i` (Linux). `--no-readonly` keeps `0644` writable. On `vfat`/`exFAT` USB the `chmod` is ignored — the tool warns `(chmod ignored by filesystem)` and you must verify with `ls -l` + `sha512sum -c SHA512SUMS`.
* Idempotent: if `DIR` already contains a file with same basename and identical `sha512`, it is reused (re-sealed) rather than duplicated as `name__1.jpg`. Different content with same basename becomes `name__1.jpg`, `__2`, etc.
* Exclusions: `kef_qr.png` (`--out`), the lock dir itself, and `SHA512SUMS`/`manifest.json` are not re-collected; `--download-random` public photos are excluded from the lock (they remain in `/tmp` for entropy only).
* `--lock-dir` cannot be inside a source path (would be re-collected next run) and `--out` inside lock warns.
* `manifest.json` is privacy-preserving by default — stores only `dst_file` + `sha512`, count, and basename of lock dir (not absolute host `src` paths). `SHA512SUMS` is standard `sha512  filename` lines.

Examples:

```bash
photo2seed photos/ --lock --words 24 --xfp
photo2seed photos/ --lock-dir ./vault --no-mix-rng --show-words
photo2seed --no-mix-rng --show-words ./perch-dog      # re-derive from lock
sha512sum -c ./vault/SHA512SUMS && cat ./vault/manifest.json
```

Unlock (remove read-only) to delete or update:

```bash
# macOS
chflags -R nouchg ./vault && chmod -R u+w ./vault && rm -rf ./vault
# Linux
chattr -R -i ./vault 2>/dev/null; chmod -R u+w ./vault && rm -rf ./vault
```

Note: with the default CSPRNG mixing, the lock alone is **not** sufficient for re-derive — the `QR + password` is the backup. Only ` --no-mix-rng` makes the lock folder a deterministic backup.

## Single binary / Tails OS

The tool builds to one static executable (Python interpreter, libraries, and
the BIP39 wordlist bundled) via PyInstaller. No Python, no packages, no
network needed on the target machine.

### Build

```bash
make            # native binary for this machine -> dist/photo2seed-<os>-<arch>
make build-linux  # Tails / Debian amd64 ELF (requires Docker) -> dist/photo2seed-linux-amd64
make check      # smoke-test the built binary (version, exit codes, leak scan, XFP, determinism)
make sha256     # write dist/SHA256SUMS
```

A GitHub Actions workflow (`.github/workflows/build.yml`) also builds
`photo2seed-linux-amd64` on every `v*` tag and attaches it plus `SHA256SUMS`
to the release. CI binaries are a convenience — **the trust anchor is
rebuilding from source yourself** (the `make build-linux` one-liner in a
clean Docker image) and comparing checksums.

### Use on Tails

1. On a trusted machine: `make build-linux && make sha256`.
2. Copy `photo2seed-linux-amd64` and `SHA256SUMS` to a USB stick.
3. Boot Tails; connect the USB stick.
4. In a terminal, copy the binary into RAM and verify **before** running:

   ```bash
   cp /media/amnesia/<usb>/photo2seed-linux-amd64 /tmp/
   cd /tmp
   sha256sum -c /media/amnesia/<usb>/SHA256SUMS
   chmod +x photo2seed-linux-amd64
   ```

5. Run against photos on the stick; write output back to the stick:

   ```bash
   ./photo2seed-linux-amd64 /media/amnesia/<usb>/photos --words 12 \
       --out /media/amnesia/<usb>/kef_qr.png
   ```

Why this is amnesic-safe: PyInstaller's `--onefile` extracts to `/tmp` at
runtime — on Tails `/tmp` is tmpfs (**RAM only**), so nothing touches the
disk; everything vanishes at shutdown. Seed material is not printed unless
`--show-words` is passed, and `/tmp` output (the default `--out` location) is
lost on reboot — copy the QR to persistent storage or a second USB stick in
the same session.

## Docker

Run photo2seed in a disposable container: photos in, QR out, container gone.
The `Dockerfile` builds a native image for your host architecture directly from
source (no PyInstaller step needed), so it works on both arm64 (Apple Silicon)
and amd64 without multi-arch emulation.

Build once:

```bash
docker build -t photo2seed .
```

Run (container is removed automatically after the QR is written):

```bash
docker run --rm -it \
  -v ~/photo:/photos:ro \
  -v ~/kefout:/out \
  photo2seed /photos --no-mix-rng --xfp --out /out/mykefQR.png
```

Notes:

- **`-it`** is needed so you can type the KEF password interactively (`getpass`).
- **Pass the directory, not a glob** — `docker run` does not expand `/photos/IMG*`
  inside the container; `PATH...` accepts a directory and walks it recursively.
- **Mount directories, not files** — Docker cannot bind-mount a non-existent
  output file. The QR lands in `~/kefout/mykefQR.png`.
- **`--rm`** deletes the container the instant it exits; nothing persists.
- Input is mounted **read-only** (`:ro`). Output persists only in `~/kefout`.
- Re-running needs `--force`, because the output file already exists on the host:
  add `--force` before `--out`.

## Krux recovery

Krux: *Load Mnemonic -> QR Code* -> scan the QR -> *Decrypt?* -> enter the
password. The plaintext entropy is loaded as a BIP39 mnemonic. The XFP shown
by Krux should match `--xfp` output.

**Before funding:** restore the QR on Krux, verify the words and XFP, and do
one small receive + spend round-trip. Consider a **BIP39 passphrase** (25th
word) on Krux for the wallet itself — the passphrase adds real entropy to the
seed, while the KEF password only protects the QR envelope.

## Security

- Run on a trusted, ideally **airgapped**, machine.
- **`--download-random` connects to the internet and uses PUBLIC photos**
  (`picsum.photos`). Anyone who fetches the same picture gets identical bytes,
  so this mode **forces CSPRNG mixing** — `--no-mix-rng` is rejected. The
  downloaded photos add auxiliary entropy only; the OS CSPRNG (256 bits) is
  what actually protects the seed. Prefer your own private, offline photos for
  real wallets.
- **The KEF password is the only secret protecting the QR**, and the envelope
  is designed for offline brute-force (PBKDF2 + 4-byte tag). Use a long random
  password (e.g. 6+ diceware words) and store it separately from the QR.
- **Photos are not secret by default** — they live in clouds, chats, and
  backups. In the default mode this does not matter (CSPRNG entropy dominates).
  In `--no-mix-rng` mode, anyone holding byte-identical copies of the photo
  files can derive the seed; the password is the only barrier.
- Photo entropy is unmeasurable and likely far below 128 bits against a
  human-model attacker; the Shannon check is a sanity filter (it rejects flat
  or near-black images), not a proof of unpredictability. That is why the OS
  CSPRNG is mixed in by default.
- Use **original files only**: messenger re-compression, cloud "optimize
  storage" downloads, and EXIF stripping all change file bytes. Only matters
  for reproducibility in `--no-mix-rng` mode.
- Seed material (words, entropy, digests) is hidden by default; anything shown
  with `--show-words` should be treated as sensitive terminal output. The XFP
  is public and may be shown freely.
- This generates a brand-new seed. It is not a recovery tool for existing
  seeds.
