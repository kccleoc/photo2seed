#!/usr/bin/env python3
"""photo2seed.py - derive a BIP39 seed from photo entropy and seal it in a
Krux KEF (Krux Encrypted Format) envelope, rendered as a base43 QR code.

Pipeline:
    photos -> Shannon quality check -> per-file SHA-512 -> ordered chain
    SHA-512 -> mix OS CSPRNG (default) -> BIP39 entropy -> 12/24 words
    -> (optional) master-key fingerprint (XFP)
    -> KEF v20 (AES-GCM) -> base43 -> QR PNG (scannable by Krux).

KEF envelope layout, version 20 (AES-GCM) parameters, PBKDF2 iteration
encoding, and the base43 alphabet are implemented to match the Krux reference:

    https://github.com/selfcustody/krux
      - src/krux/kef.py
      - src/krux/baseconv.py
      - docs/getting-started/features/encryption/kef-specifications.en.md

KEF (v20 AES-GCM QR) output is ALWAYS the default.

Security notes (also in README.md):
  - Run on a trusted, ideally airgapped, machine.
  - Seed material (words, entropy, hashes) is NOT printed unless --show-words.
  - OS CSPRNG entropy is mixed in by default; --no-mix-rng restores the
    photo-reproducible mode, which is safe ONLY if the photo files themselves
    stay secret (anyone holding byte-identical copies can derive the seed).
  - The KEF password is the ONLY secret protecting the QR. A weak password
    offers no real protection.

GitHub: https://github.com/kccleoc/photo2seed
"""

import argparse
import getpass
import hashlib
import hmac
import math
import os
import re
import sys
import unicodedata

import qrcode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PIL import Image, ImageDraw, ImageFont

from ripemd160 import ripemd160

# Enable Pillow support for HEIC/HEIF (iPhone photos); no-op if not installed
try:
    from pillow_heif import register_heif_opener

    register_heif_opener()
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

B43CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:"
IMAGE_EXTENSIONS = (
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp",
    ".heic", ".heif", ".avif",
)

KEF_VERSION_GCM = 20
QR_CODE_ITER_MULTIPLE = 10000

APP_VERSION = "1.1.0"
GITHUB_URL = "https://github.com/kccleoc/photo2seed"

# Official BIP39 English wordlist fingerprint (verified at load time)
WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

BIP39_WORDLIST = []


def resource_path(name):
    """Resolve a bundled data file, both as script and as PyInstaller binary."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)


# ---------------------------------------------------------------------------
# Path / photo discovery
# ---------------------------------------------------------------------------


def collect_photos(paths):
    """Expand each CLI path into a list of image files (files or dirs, recursive)."""
    files = []
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, names in os.walk(p):
                for name in sorted(names):
                    full = os.path.join(root, name)
                    if name.lower().endswith(IMAGE_EXTENSIONS):
                        files.append(full)
        elif os.path.isfile(p):
            if p.lower().endswith(IMAGE_EXTENSIONS):
                files.append(p)
            else:
                print("[warn] not an image (skipping): %s" % p)
        else:
            print("[warn] path not found (skipping): %s" % p)
    # de-dupe preserving first occurrence
    seen, uniq = set(), []
    for f in files:
        real = os.path.realpath(f)
        if real not in seen:
            seen.add(real)
            uniq.append(f)
    return uniq


# ---------------------------------------------------------------------------
# Shannon distribution check
# ---------------------------------------------------------------------------


def shannon_analysis(path):
    """Return (shannon_entropy_bits, mean_brightness_0_255) for a grayscale photo."""
    with Image.open(path) as img:
        hist = img.convert("L").histogram()
    total = float(sum(hist))
    if total == 0:
        return 0.0, 0.0
    probs = [h / total for h in hist]
    entropy = -sum(p * math.log2(p) for p in probs if p > 0)
    mean = sum(i * p for i, p in enumerate(probs))
    return entropy, mean


# ---------------------------------------------------------------------------
# SHA-512 ordering + chained digest
# ---------------------------------------------------------------------------


def natural_key(name):
    """Natural sort key so 'photo10' sorts after 'photo9'."""
    return [int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", name)]


def sha512_file(path, chunk_size=1 << 20):
    h = hashlib.sha512()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.digest()


def final_chain_hash(digests):
    """final = SHA512( sha512(p1) + sha512(p2) + ... ) over hex digests."""
    acc = hashlib.sha512()
    for d in digests:
        acc.update(d.hex().encode("ascii"))
    return acc.digest()


# ---------------------------------------------------------------------------
# BIP39 (Ian Coleman method)
# ---------------------------------------------------------------------------


def load_wordlist(path):
    global BIP39_WORDLIST
    with open(path, "rb") as f:
        raw = f.read()
    if hashlib.sha256(raw).hexdigest() != WORDLIST_SHA256:
        raise SystemExit(
            "[fatal] english.txt SHA-256 mismatch - not the official BIP39 wordlist"
        )
    words = raw.decode("ascii").split()
    if len(words) != 2048:
        raise SystemExit("[fatal] BIP39 wordlist has %d words, expected 2048" % len(words))
    BIP39_WORDLIST = words


def mnemonic_from_entropy(entropy):
    """Convert ENT bytes of entropy to BIP39 mnemonic words (IAN COLEMAN method)."""
    ent = len(entropy) * 8
    if ent not in (128, 256):
        raise ValueError("entropy must be 16 or 32 bytes")
    cs = ent // 32
    h = int.from_bytes(hashlib.sha256(entropy).digest(), "big")
    checksum_bits = h >> (256 - cs)
    data = (int.from_bytes(entropy, "big") << cs) | checksum_bits
    total_bits = ent + cs
    words = []
    for i in range(total_bits // 11):
        shift = total_bits - 11 * (i + 1)
        index = (data >> shift) & 0x7FF
        words.append(BIP39_WORDLIST[index])
    return words


# ---------------------------------------------------------------------------
# Master key fingerprint (XFP) - BIP32 / BIP39
# ---------------------------------------------------------------------------


def hash160(data):
    """HASH160 = RIPEMD160(SHA256(data))."""
    return ripemd160(hashlib.sha256(data).digest())


def seed_from_mnemonic(words):
    """BIP39: seed = PBKDF2-HMAC-SHA512(passphrase, salt=b'mnemonic', 2048)."""
    mnemonic = unicodedata.normalize("NFKD", " ".join(words)).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", mnemonic, b"mnemonic", 2048)


def master_key_fingerprint(words):
    """BIP32 master key fingerprint (XFP): first 4 bytes of HASH160(master pubkey)."""
    seed = seed_from_mnemonic(words)
    i = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    il = int.from_bytes(i[:32], "big")
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    if il == 0:  # derive_private_key validates il < n
        raise ValueError("invalid master key (IL == 0)")
    priv = ec.derive_private_key(il, ec.SECP256K1())
    pub = priv.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    return hash160(pub)[:4].hex().upper()


# ---------------------------------------------------------------------------
# KEF v20 (AES-GCM) - reference-matching implementation
# ---------------------------------------------------------------------------


def kef_key(key, salt, iterations):
    """pbkdf2_hmac_sha256(K, id, i) - matches kef.Cipher key derivation."""
    key = key.encode("utf-8") if isinstance(key, str) else key
    salt = salt.encode("utf-8") if isinstance(salt, str) else salt
    return hashlib.pbkdf2_hmac("sha256", key, salt, iterations)


def kef_encrypt_gcm(derived_key, plaintext, nonce=None):
    """AES-256-GCM, 12-byte nonce, first 4 bytes of tag exposed. Returns (payload, full_tag)."""
    if nonce is None:
        nonce = os.urandom(12)
    if len(nonce) != 12:
        raise ValueError("GCM nonce must be 12 bytes")
    ct_full = AESGCM(derived_key).encrypt(nonce, plaintext, None)
    ciphertext, full_tag = ct_full[:-16], ct_full[-16:]
    payload = nonce + ciphertext + full_tag[:4]
    return payload, full_tag


def kef_wrap(id_, version, iterations, payload):
    """len_id + id + version + iterations(3B big) + payload - matches kef.wrap()."""
    id_ = id_.encode("utf-8") if isinstance(id_, str) else id_
    if not 0 <= len(id_) <= 252:
        raise ValueError("Invalid ID length")
    len_id = len(id_).to_bytes(1, "big")

    if iterations % QR_CODE_ITER_MULTIPLE == 0:
        stored = iterations // QR_CODE_ITER_MULTIPLE
        if not 1 <= stored <= 10000:
            raise ValueError("Invalid iterations")
    else:
        stored = iterations
        if not 10000 < stored < 2**24:
            raise ValueError("Invalid iterations")
    iter_bytes = stored.to_bytes(3, "big")

    return b"".join([len_id, id_, version.to_bytes(1, "big"), iter_bytes, payload])


def kef_unwrap(envelope):
    """Parse a KEF envelope -> (id_bytes, version, effective_iterations, payload)."""
    len_id = envelope[0]
    id_ = envelope[1 : 1 + len_id]
    version = envelope[1 + len_id]
    stored = int.from_bytes(envelope[2 + len_id : 5 + len_id], "big")
    iterations = stored * QR_CODE_ITER_MULTIPLE if stored <= 10000 else stored
    payload = envelope[5 + len_id :]
    return id_, version, iterations, payload


def kef_decrypt_gcm(derived_key, payload):
    """Decrypt a v20 payload WITHOUT tag verification (tag truncated to 4 bytes).

    KEF truncates the GCM auth tag to 4 bytes (advisory only), which
    cryptography's AESGCM refuses to verify. GCM ciphertext is plain AES-CTR
    with keystream from inc32(J0); re-derive it here and decrypt the raw CT.
    """
    nonce = payload[:12]
    body = payload[12:]
    if len(body) < 17:
        raise ValueError("Invalid v20 payload")
    ct, _auth = body[:-4], body[-4:]
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    # J0 = nonce || 0^31 || 1  ;  ciphertext keystream starts at inc32(J0)
    j0 = (int.from_bytes(nonce, "big") << 32) | 1
    keystream_start = (j0 + 1).to_bytes(16, "big")
    dec = Cipher(algorithms.AES(derived_key), modes.CTR(keystream_start)).decryptor()
    return dec.update(ct) + dec.finalize()


def validate_iterations(iterations):
    """Ensure the iteration count is encodable in a KEF envelope (see kef_wrap)."""
    if iterations % QR_CODE_ITER_MULTIPLE == 0:
        stored = iterations // QR_CODE_ITER_MULTIPLE
        if 1 <= stored <= 10000:
            return
    elif 10000 < iterations < 2**24:
        return
    raise SystemExit(
        "[fatal] --iterations %d cannot be encoded in a KEF envelope. Use a "
        "multiple of %d (max %d) or a raw value between 10001 and %d."
        % (iterations, QR_CODE_ITER_MULTIPLE,
           QR_CODE_ITER_MULTIPLE * 10000, 2**24 - 1)
    )


def base43_encode(v):
    """Encode bytes to base43 (Krux B43CHARS) - matches pure_python_base_encode."""
    chars = B43CHARS
    long_value = 0
    power = 1
    for char in reversed(v):
        long_value += power * char
        power <<= 8
    out = bytearray()
    while long_value >= 43:
        long_value, mod = divmod(long_value, 43)
        out.extend(chars[mod].encode())
    if long_value > 0:
        out.extend(chars[long_value].encode())
    n_pad = 0
    for char in v:
        if char == 0:
            n_pad += 1
        else:
            break
    if n_pad > 0:
        out.extend((chars[0] * n_pad).encode())
    return bytes(reversed(out)).decode()


def base43_decode(v):
    chars = B43CHARS
    long_value = 0
    power = 1
    for char in reversed(v):
        digit = chars.find(char)
        if digit == -1:
            raise ValueError("forbidden char %r for base43" % char)
        long_value += digit * power
        power *= 43
    out = bytearray()
    while long_value >= 256:
        long_value, mod = divmod(long_value, 256)
        out.append(mod)
    if long_value > 0:
        out.append(long_value)
    n_pad = 0
    for char in v:
        if char == chars[0]:
            n_pad += 1
        else:
            break
    if n_pad > 0:
        out.extend(b"\x00" * n_pad)
    return bytes(reversed(out))


# ---------------------------------------------------------------------------
# Key strength heuristic (mirrors Krux EncryptionKey.key_strength)
# ---------------------------------------------------------------------------


def key_strength(key_string):
    if len(key_string) < 8:
        return "Weak"
    has_upper = has_lower = has_digit = has_special = False
    for c in key_string:
        if "a" <= c <= "z":
            has_lower = True
        elif "A" <= c <= "Z":
            has_upper = True
        elif "0" <= c <= "9":
            has_digit = True
        else:
            has_special = True
        if has_upper and has_lower and has_digit and has_special:
            break
    score = sum([has_upper, has_lower, has_digit, has_special])
    klen = len(key_string)
    if klen >= 12:
        score += 1
    if klen >= 16:
        score += 1
    if klen >= 20:
        score += 1
    if klen >= 40:
        score += 1
    set_len = len(set(key_string))
    if set_len < 6:
        score -= 1
    if set_len < 3:
        score -= 1
    if score >= 4:
        return "Strong"
    if score >= 3:
        return "Medium"
    return "Weak"


def prompt_password():
    pw = getpass.getpass("KEF encrypt password: ")
    confirm = getpass.getpass("Confirm password: ")
    if pw != confirm:
        print("[error] passwords do not match", file=sys.stderr)
        sys.exit(2)
    if not pw:
        print("[error] empty password rejected", file=sys.stderr)
        sys.exit(2)
    strength = key_strength(pw)
    print("Key strength: %s" % strength)
    if strength == "Weak":
        print("[warn] WEAK key offers NO protection per KEF spec. Use a long random key.")
        resp = input("Continue anyway? [y/N] ")
        if resp.strip().lower() not in ("y", "yes"):
            sys.exit(2)
    return pw


# ---------------------------------------------------------------------------
# QR output
# ---------------------------------------------------------------------------


def render_qr(data, out_path, top_text=None, bottom_text=None):
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=8, border=4)
    qr.add_data(data)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    qr_w, qr_h = qr_img.size

    font_top = ImageFont.load_default(size=34)
    font_bottom = ImageFont.load_default(size=26)
    pad_x, pad_y = 16, 12

    probe = Image.new("RGB", (1, 1), "white")
    probe_draw = ImageDraw.Draw(probe)

    def glyph_h(draw, font, text):
        bbox = draw.textbbox((0, 0), text, font=font)
        return bbox[3] - bbox[1]

    def glyph_w(draw, font, text):
        bbox = draw.textbbox((0, 0), text, font=font)
        return bbox[2] - bbox[0]

    def band_height(draw, font, text):
        return glyph_h(draw, font, text) + 2 * pad_y

    top_h = band_height(probe_draw, font_top, top_text) if top_text else 0
    bot_h = band_height(probe_draw, font_bottom, bottom_text) if bottom_text else 0
    inner_w = max(qr_w, 2 * pad_x)
    if top_text:
        inner_w = max(inner_w, glyph_w(probe_draw, font_top, top_text) + 2 * pad_x)
    if bottom_text:
        inner_w = max(inner_w, glyph_w(probe_draw, font_bottom, bottom_text) + 2 * pad_x)

    canvas = Image.new("RGB", (inner_w, top_h + qr_h + bot_h), "white")
    canvas.paste(qr_img, ((inner_w - qr_w) // 2, top_h))
    draw = ImageDraw.Draw(canvas)

    def center(font, text, x_center, y_center):
        draw.text((x_center, y_center), text, font=font, fill="black", anchor="mm")

    if top_text:
        center(font_top, top_text, inner_w // 2,
               pad_y + glyph_h(draw, font_top, top_text) // 2)
    if bottom_text:
        center(font_bottom, bottom_text, inner_w // 2,
               top_h + qr_h + pad_y + glyph_h(draw, font_bottom, bottom_text) // 2)

    canvas.save(out_path)
    print("QR saved: %s (%dx%d px)" % (out_path, inner_w, top_h + qr_h + bot_h))


# ---------------------------------------------------------------------------
# install / uninstall
# ---------------------------------------------------------------------------


def _user_bin():
    home_bin = os.path.join(os.path.expanduser("~"), ".local", "bin")
    for p in os.environ.get("PATH", "").split(":"):
        if p and os.path.exists(p) and os.path.samefile(home_bin, p):
            return home_bin
    return "/usr/local/bin"


def _launcher_target():
    """(executable, [script]) that this program should be launched through."""
    if getattr(sys, "frozen", False):
        return sys.executable, []
    return sys.executable, [os.path.abspath(__file__)]


def cmd_install():
    exe, script = _launcher_target()
    dest = os.path.join(_user_bin(), "photo2seed")
    if script:
        body = '#!/bin/sh\nexec "%s" "%s" "$@"\n' % (exe, script[0])
    else:
        body = '#!/bin/sh\nexec "%s" "$@"\n' % exe
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "w") as f:
        f.write(body)
    os.chmod(dest, 0o755)
    print("Installed launcher: %s" % dest)
    print("PATH note: if '%s' is not on your PATH, add it or restart your shell." % os.path.dirname(dest))
    print("Run 'photo2seed --help' to get started.")


def cmd_uninstall():
    dest = os.path.join(_user_bin(), "photo2seed")
    if os.path.exists(dest):
        os.remove(dest)
        print("Removed: %s" % dest)
    else:
        print("Nothing to uninstall: %s does not exist" % dest)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

EPILOG = """\
examples:
  photo2seed ~/Pictures/trip/                  default: words -> KEF QR PNG + password
  photo2seed a.jpg some/dir/ --words 24        24-word seed
  photo2seed photos/ --show-words              also print words/entropy/hashes
  photo2seed photos/ --xfp                     also show master-key fingerprint (XFP)
  photo2seed photos/ --derive-only --xfp       show ONLY the XFP (no words, no KEF)
  photo2seed install                           add 'photo2seed' to your user bin dir
  photo2seed uninstall                         remove the 'photo2seed' launcher

KEF (v20 AES-GCM QR) output is ALWAYS the default. The KEF password is the
only secret protecting the QR - use a long random password.

GitHub: %s
""" % GITHUB_URL


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("install", "uninstall"):
        (cmd_install if sys.argv[1] == "install" else cmd_uninstall)()
        return

    ap = argparse.ArgumentParser(
        prog="photo2seed",
        description="Photo entropy + OS CSPRNG -> BIP39 seed -> Krux KEF v20 (AES-GCM) -> base43 QR",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "--version",
        action="version",
        version="photo2seed %s (%s)" % (APP_VERSION, GITHUB_URL),
    )
    ap.add_argument("paths", nargs="+", help="photo files and/or directories")
    ap.add_argument(
        "--words",
        type=int,
        choices=(12, 24),
        default=12,
        help="BIP39 mnemonic length (default 12)",
    )
    ap.add_argument(
        "--id",
        default=None,
        help="KEF envelope ID / PBKDF2 salt (default: random per envelope)",
    )
    ap.add_argument(
        "--iterations",
        type=int,
        default=1000000,
        help="PBKDF2-HMAC-SHA256 iterations (default 1000000)",
    )
    ap.add_argument(
        "--out",
        default="kef_qr.png",
        help="output QR PNG path (default kef_qr.png)",
    )
    ap.add_argument(
        "--label",
        default=None,
        help="custom text printed under the QR (max 20 chars; default 'KEF QR')",
    )
    ap.add_argument(
        "--min-entropy",
        type=float,
        default=7.0,
        help="minimum Shannon entropy in bits (default 7.0)",
    )
    ap.add_argument(
        "--min-brightness",
        type=float,
        default=30.0,
        help="minimum mean brightness 0-255 (default 30.0)",
    )
    ap.add_argument(
        "--show-words",
        action="store_true",
        help="print the BIP39 words and all seed material (entropy, digests)",
    )
    ap.add_argument(
        "--xfp",
        action="store_true",
        help="print the master-key fingerprint (XFP) of the derived seed",
    )
    ap.add_argument(
        "--no-mix-rng",
        action="store_true",
        help="derive entropy from photos only (reproducible, but anyone with "
        "byte-identical photo files can derive the seed)",
    )
    ap.add_argument(
        "--derive-only",
        action="store_true",
        help="derive the words only; no password prompt, no envelope, no QR",
    )
    ap.add_argument(
        "--force",
        action="store_true",
        help="overwrite the output QR file if it exists",
    )
    args = ap.parse_args()

    validate_iterations(args.iterations)
    if not 0 <= args.min_entropy <= 8:
        raise SystemExit("[fatal] --min-entropy must be between 0 and 8")
    if not 0 <= args.min_brightness <= 255:
        raise SystemExit("[fatal] --min-brightness must be between 0 and 255")
    if args.label is not None and len(args.label) > 20:
        raise SystemExit("[fatal] --label must be 20 characters or fewer")

    load_wordlist(resource_path("english.txt"))

    args.id = args.id or ("kef-photo-" + os.urandom(6).hex())

    if not args.derive_only and os.path.exists(args.out) and not args.force:
        raise SystemExit(
            "[fatal] output file %s already exists (use --force to overwrite)" % args.out
        )

    photos = collect_photos(args.paths)
    if not photos:
        print("[error] no photos found", file=sys.stderr)
        sys.exit(2)

    print("== Photo Shannon quality check ==")
    accepted = []
    for p in photos:
        try:
            entropy, mean = shannon_analysis(p)
        except Exception as exc:  # noqa: BLE001 - a broken image should not kill the run
            print("  REJECT %-50s unreadable (%s)" % (os.path.basename(p), exc))
            continue
        ok = entropy >= args.min_entropy and mean >= args.min_brightness
        status = "PASS" if ok else "REJECT"
        print(
            "  %-6s %-50s H=%6.3f bits  mean=%6.1f/255"
            % (status, os.path.basename(p), entropy, mean)
        )
        if ok:
            accepted.append(p)

    if not accepted:
        print("[error] all photos rejected by the Shannon check", file=sys.stderr)
        sys.exit(2)

    total_bytes = sum(os.path.getsize(p) for p in accepted)
    if len(accepted) < 3 or total_bytes < 5 * 1024 * 1024:
        print(
            "[warn] thin entropy input: %d photo(s), %.1f MB total. "
            "Use more high-detail original photos."
            % (len(accepted), total_bytes / 1048576.0),
            file=sys.stderr,
        )

    # prompt BEFORE hashing so a mistyped confirmation does not waste the run
    password = None if args.derive_only else prompt_password()

    entries = []
    for p in accepted:
        digest = sha512_file(p)
        entries.append((p, digest))
    entries.sort(key=lambda e: (natural_key(os.path.basename(e[0])), e[1].hex()))
    if args.show_words:
        print("\n== SHA-512 digest (ordered by filename, then digest) ==")
        for p, d in entries:
            print("  %-50s sha512=%s" % (os.path.basename(p), d.hex()))

    final = final_chain_hash([d for _, d in entries])
    if args.show_words:
        print("\nFinal SHA-512: %s" % final.hex())

    if args.no_mix_rng:
        print(
            "\n[warn] --no-mix-rng: the seed is reproducible from the photo files "
            "alone; anyone with byte-identical copies can derive it. The KEF "
            "password is the only barrier."
        )
    else:
        final = hashlib.sha512(final + os.urandom(32)).digest()
        print(
            "\nMixed OS CSPRNG entropy: the seed is NOT reproducible from the "
            "photos alone - the QR + password is the backup."
        )

    ent_bytes = final[: 16 if args.words == 12 else 32]
    if args.show_words:
        print("BIP39 entropy (%d bytes): %s" % (len(ent_bytes), ent_bytes.hex()))

    words = mnemonic_from_entropy(ent_bytes)
    if args.show_words:
        print("\nBIP39 words (%d):" % len(words))
        for i in range(0, len(words), 3):
            cells = [
                "%2d.%-8s" % (i + j + 1, words[i + j])
                for j in range(3)
                if i + j < len(words)
            ]
            print("  " + "  ".join(cells))
    else:
        print("\nBIP39 words: [hidden - use --show-words to display]")

    xfp = None
    if args.xfp or not args.derive_only:
        xfp = master_key_fingerprint(words)
    if args.xfp:
        print("XFP: %s" % xfp)

    if args.derive_only:
        if not args.no_mix_rng:
            print(
                "\n[--derive-only] With CSPRNG mixing on, every run derives "
                "fresh words; photos only reproduce the seed when --no-mix-rng "
                "is used."
            )
        else:
            print("\n[--derive-only] No KEF envelope or QR written.")
        return

    # --- KEF encrypt (v20 AES-GCM) ---
    derived = kef_key(password, args.id, args.iterations)

    plaintext = ent_bytes
    payload, _full_tag = kef_encrypt_gcm(derived, plaintext)
    envelope = kef_wrap(args.id, KEF_VERSION_GCM, args.iterations, payload)

    # self-test: unwrap + decrypt (without tag verification) must round-trip
    _id2, _ver2, _it2, payload2 = kef_unwrap(envelope)
    back = kef_decrypt_gcm(derived, payload2)
    if back != plaintext:
        print("[error] KEF round-trip self-test FAILED", file=sys.stderr)
        sys.exit(3)
    if base43_decode(base43_encode(envelope)) != envelope:
        print("[error] base43 round-trip self-test FAILED", file=sys.stderr)
        sys.exit(3)

    print("\n== KEF envelope ==")
    print("  ID: %s" % args.id)
    print("  Version: AES-GCM (v%d)" % KEF_VERSION_GCM)
    print("  PBKDF2 iter.: %d" % args.iterations)
    print("  Envelope bytes: %d" % len(envelope))

    b43 = base43_encode(envelope)
    print("\nKEF base43 (%d chars):" % len(b43))
    for i in range(0, len(b43), 64):
        print("  %s" % b43[i : i + 64])

    render_qr(
        b43,
        args.out,
        top_text="XFP: %s" % xfp,
        bottom_text=args.label if args.label is not None else "KEF QR",
    )

    print(
        "\nKrux recovery: load mnemonic -> QR Code; scan this QR; choose "
        "'Decrypt?' and enter the password.\n"
        "Before funding: restore on Krux, verify the words (and XFP), and do "
        "one small receive + spend round-trip."
    )


if __name__ == "__main__":
    main()
