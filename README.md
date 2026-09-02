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
```

Default behavior: photos in → seed derived → **KEF password prompted** →
**KEF QR PNG written**. Seed material is **not printed** unless you pass
`--show-words`.

`PATH...` accepts one or more image files and/or directories (recursive).

Examples:

```bash
photo2seed ~/Pictures/trip/                  # default: words -> KEF QR PNG + password
photo2seed a.jpg some/dir/ --words 24         # 24-word seed
photo2seed photos/ --show-words              # also print words/entropy/hashes
photo2seed photos/ --xfp                     # also show the master-key fingerprint
photo2seed photos/ --derive-only --xfp       # show ONLY the XFP (no words, no KEF)
photo2seed install / photo2seed uninstall    # add / remove the command
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--words 12\|24` | `12` | BIP39 mnemonic length (128 / 256-bit entropy) |
| `--id LABEL` | random per envelope | KEF envelope ID, also the PBKDF2 salt |
| `--iterations N` | `1000000` | PBKDF2-HMAC-SHA256 iterations |
| `--out FILE` | `kef_qr.png` | Output QR PNG path (refused if exists, unless `--force`) |
| `--show-words` | off | Print words, entropy, and SHA-512 digests |
| `--xfp` | off | Print the master-key fingerprint (XFP) of the derived seed |
| `--no-mix-rng` | off | Use photo entropy only (reproducible mode — see below) |
| `--derive-only` | off | Derive words only: no password, no envelope, no QR |
| `--force` | off | Overwrite an existing output QR file |
| `--min-entropy BITS` | `7.0` | Reject photos with Shannon entropy below this |
| `--min-brightness 0-255` | `30.0` | Reject photos with mean brightness below this |

## XFP (master-key fingerprint)

`--xfp` computes the BIP32 master-key fingerprint of the derived seed and
prints it as 8 uppercase hex chars, e.g. `XFP: 73C5DA0A`. It is a **public,
non-secret identifier** — the same value shown by Krux, Specter, and most
wallets — so it is printed even without `--show-words`. Use it to confirm that
a wallet/Krux holds the same seed you generated, without exposing the words.
Pair with `--derive-only` to show nothing else:

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
3. **Prompt for the KEF password** (twice, via `getpass`) — before hashing, so
   a mistyped confirmation does not waste the run.
4. **SHA-512** each accepted photo (whole file, EXIF included).
5. **Order** accepted photos by filename (natural sort), tie-break by digest.
6. **Chain hash** = `SHA512( sha512(p₁) ‖ sha512(p₂) ‖ … )` over hex digests.
7. **Mix OS CSPRNG** (default): `chain = SHA512( chain ‖ os.urandom(32) )`.
   With `--no-mix-rng` this step is skipped.
8. **BIP39 entropy** = first 16 bytes (12 words) or 32 bytes (24 words).
9. **Words** — Ian Coleman method: SHA-256 checksum, 11-bit groups into the
   vendored `english.txt` (SHA-256-verified against the official BIP39 list at
   load time). Printed with BIP39 index numbers when `--show-words` is given.
10. **XFP** (optional) — BIP32 master-key fingerprint of the derived seed.
11. **KEF v20 (AES-GCM)** — plaintext is the entropy bytes; key =
    `pbkdf2_hmac_sha256(password, id, iterations)`; 12-byte random nonce; first
    4 bytes of the auth tag exposed; envelope = `len_id + id + 20 + iterations(3B)
    + nonce + ciphertext + tag`. A round-trip self-test decrypts the envelope
    before output.
12. **QR** — base43-encode the envelope, render a PNG.

## Determinism — two modes

- **Default (CSPRNG mixed):** the same photos produce *different* seeds on
  every run. The **QR + password is the backup** — the photos alone are not
  sufficient to recover the seed. This is the safe default: neither a photo
  leak nor a compromised system RNG alone can reveal the seed.
- **`--no-mix-rng`:** the same unmodified photos always produce the same words
  (the KEF nonce and ciphertext differ every run). Reproducible-from-photos
  mode is only safe if the exact photo files are kept secret — see Security.

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
