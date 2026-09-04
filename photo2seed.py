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
import json
import math
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import unicodedata
import urllib.request

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

# Memorable two-word lock folder name (human-readable, easy to recall)
LOCK_WORDS_1 = (
    "perch", "gaze", "calm", "bold", "swift", "bright", "quiet", "amber",
    "river", "forest", "ocean", "sunset", "crisp", "lunar", "coral", "velvet",
    "keen", "brave", "frost", "humble", "silent", "gold", "iron", "cedar",
    "maple", "autumn", "crimson", "azure", "ember", "harbor", "meadow", "summit",
)

LOCK_WORDS_2 = (
    "dog", "man", "owl", "fox", "wolf", "bear", "hawk", "stone", "light",
    "pine", "dune", "ridge", "vale", "crest", "grove", "field", "shore", "peak",
    "brook", "canyon", "falcon", "puma", "otter", "raven", "heron", "bison",
    "elk", "seal", "wren", "lark", "finch", "thrush",
)


def resource_path(name):
    """Resolve a bundled data file, both as script and as PyInstaller binary."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)


def get_system_temp_dir():
    """Return system temp dir, always /tmp on POSIX (not /var/folders), fallback to tempfile.gettempdir."""
    if sys.platform == "win32":
        return os.environ.get("TEMP") or os.environ.get("TMP") or tempfile.gettempdir()
    # POSIX: prefer /tmp (and /private/tmp on macOS) over $TMPDIR (/var/folders)
    for cand in ("/tmp", "/private/tmp"):
        if os.path.isdir(cand) and os.access(cand, os.W_OK):
            return cand
    return tempfile.gettempdir()


SYSTEM_TEMP = get_system_temp_dir()  # evaluated at import for legacy; prefer get_system_temp_dir() live


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
# Photo lock — memorable folder + read-only seal
# ---------------------------------------------------------------------------


def generate_memorable_name():
    """Return a human-readable two-word name like 'perch-dog' or 'gaze-man'."""
    w1 = secrets.choice(LOCK_WORDS_1)
    w2 = secrets.choice(LOCK_WORDS_2)
    return f"{w1}-{w2}"


def resolve_lock_dir(lock_arg, lock_dir_arg):
    """Resolve --lock / --lock-dir into a concrete directory path or None."""
    if lock_arg and lock_dir_arg:
        raise SystemExit("[fatal] use only one of --lock or --lock-dir")
    if lock_arg:
        base = os.getcwd()  # durable archive should stay in cwd, not /tmp (purged on reboot)
        for _ in range(100):
            name = generate_memorable_name()
            candidate = os.path.join(base, name)
            if not os.path.exists(candidate):
                return candidate
        # fallback: append nonce
        return os.path.join(base, generate_memorable_name() + "-%d" % (time.time_ns() % 10000))
    if lock_dir_arg is not None:
        if not lock_dir_arg.strip():
            raise SystemExit("[fatal] --lock-dir requires a non-empty path")
        return lock_dir_arg
    return None


def clear_immutable(path):
    """Best-effort clear immutable flag so file can be overwritten/removed."""
    try:
        if sys.platform == "darwin":
            subprocess.run(["chflags", "nouchg", path], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        elif sys.platform.startswith("linux"):
            subprocess.run(["chattr", "-i", path], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
    except Exception:  # noqa: BLE001
        pass
    try:
        # ensure writable for overwrite
        mode = os.stat(path).st_mode
        if not (mode & 0o200):
            os.chmod(path, mode | 0o200)
    except Exception:  # noqa: BLE001
        pass


def seal_readonly(path):
    """Make file at path read-only (0444) and best-effort immutable; return (ok, note)."""
    try:
        os.chmod(path, 0o444)
    except Exception as exc:  # noqa: BLE001
        return False, "chmod failed: %s" % exc
    # best-effort OS immutable bits (ignore failures - FAT32, permission, etc.)
    note = ""
    try:
        if sys.platform == "darwin":
            subprocess.run(["chflags", "uchg", path], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        elif sys.platform.startswith("linux"):
            subprocess.run(["chattr", "+i", path], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
    except Exception:  # noqa: BLE001
        pass
    # verify chmod stuck (FAT32 may ignore)
    try:
        mode = os.stat(path).st_mode & 0o777
        if mode & 0o222:
            note = " (chmod ignored by filesystem)"
    except Exception:  # noqa: BLE001
        pass
    return True, note


def _is_subpath(child, parent):
    """True if child is inside parent (both absolute)."""
    try:
        child_r = os.path.realpath(os.path.abspath(child))
        parent_r = os.path.realpath(os.path.abspath(parent))
        # child == parent is also considered subpath for exclusion
        if child_r == parent_r:
            return True
        return os.path.commonpath([child_r, parent_r]) == parent_r
    except Exception:  # noqa: BLE001
        return False


def archive_pass_photos(accepted, digests_by_path, dest_dir, readonly=True, with_manifest=True):
    """Copy PASS photos to dest_dir, seal read-only, write manifest.

    accepted: list of source paths that passed Shannon.
    digests_by_path: dict src -> sha512 hex (or bytes) for verification.
    Returns (dest_paths, lock_dir) where dest_paths are the copied files.
    """
    # fail-fast if dest exists as file
    if os.path.lexists(dest_dir) and not os.path.isdir(dest_dir):
        raise SystemExit("[fatal] --lock-dir exists and is not a directory: %s" % dest_dir)
    try:
        os.makedirs(dest_dir, exist_ok=True)
    except FileExistsError:
        raise SystemExit("[fatal] --lock-dir exists and is not a directory: %s" % dest_dir)
    except OSError as exc:  # noqa: BLE001
        raise SystemExit("[fatal] cannot create lock dir %s (%s)" % (dest_dir, exc))
    if not os.path.isdir(dest_dir):
        raise SystemExit("[fatal] --lock-dir is not a directory: %s" % dest_dir)

    dest_paths = []
    manifest_entries = []
    # existing files in dest_dir (for collision handling)
    try:
        existing = set(os.listdir(dest_dir))
    except Exception:  # noqa: BLE001
        existing = set()
    seen_basenames = set(existing)

    for src in accepted:
        base = os.path.basename(src)
        src_hex = digests_by_path.get(src)
        if src_hex is None:
            src_hex = sha512_file(src).hex()

        dest_name = base
        dst = os.path.join(dest_dir, dest_name)
        # if file exists, check if byte-identical -> reuse instead of duplicate
        if os.path.exists(dst):
            try:
                existing_hex = sha512_file(dst).hex()
                if existing_hex == src_hex:
                    # identical -> keep single copy, re-seal (clear uchg first then seal)
                    if readonly:
                        clear_immutable(dst)
                    seen_basenames.add(dest_name)
                    note = ""
                    if readonly:
                        _ok, note = seal_readonly(dst)
                    dest_paths.append(dst)
                    manifest_entries.append({
                        "src": src,
                        "dst_file": dest_name,
                        "sha512": existing_hex,
                        "readonly_note": note,
                    })
                    if readonly and note:
                        print("[warn] %s chmod ignored (filesystem may not support permissions)" % dst, file=sys.stderr)
                    continue
            except Exception:  # noqa: BLE001
                pass
            # hash differs or unreadable -> need collision suffix
            if dest_name in seen_basenames:
                stem, ext = os.path.splitext(base)
                counter = 1
                while True:
                    candidate = f"{stem}__{counter}{ext}"
                    cand_path = os.path.join(dest_dir, candidate)
                    if candidate not in seen_basenames and not os.path.exists(cand_path):
                        dest_name = candidate
                        dst = cand_path
                        break
                    # if candidate exists and is identical, reuse it
                    if os.path.exists(cand_path):
                        try:
                            cand_hex = sha512_file(cand_path).hex()
                            if cand_hex == src_hex:
                                if readonly:
                                    clear_immutable(cand_path)
                                seen_basenames.add(candidate)
                                note = ""
                                if readonly:
                                    _ok, note = seal_readonly(cand_path)
                                dest_paths.append(cand_path)
                                manifest_entries.append({
                                    "src": src,
                                    "dst_file": candidate,
                                    "sha512": cand_hex,
                                    "readonly_note": note,
                                })
                                dest_name = None  # signal skip copy
                                break
                        except Exception:  # noqa: BLE001
                            pass
                    counter += 1
                if dest_name is None:
                    continue
        elif dest_name in seen_basenames:
            # name already used in this run (but file not on disk yet from earlier src in same run)
            stem, ext = os.path.splitext(base)
            counter = 1
            while True:
                candidate = f"{stem}__{counter}{ext}"
                if candidate not in seen_basenames and not os.path.exists(os.path.join(dest_dir, candidate)):
                    dest_name = candidate
                    dst = os.path.join(dest_dir, candidate)
                    break
                counter += 1
        seen_basenames.add(dest_name)
        try:
            # ensure dest's parent flags cleared before overwrite
            if os.path.exists(dst):
                clear_immutable(dst)
            shutil.copy2(src, dst)
        except Exception as exc:  # noqa: BLE001
            print("[warn] lock copy failed %s -> %s (%s)" % (src, dst, exc), file=sys.stderr)
            continue
        # verify byte-identical via sha512
        src_hex = digests_by_path.get(src)
        if src_hex is None:
            src_hex = sha512_file(src).hex()
        try:
            dst_hex = sha512_file(dst).hex()
        except Exception as exc:  # noqa: BLE001
            print("[warn] lock verify failed for %s (%s)" % (dst, exc), file=sys.stderr)
            dst_hex = ""
        if src_hex != dst_hex:
            print("[warn] lock hash mismatch %s (src %s != dst %s)" % (dst, src_hex[:12], dst_hex[:12]), file=sys.stderr)
        note = ""
        if readonly:
            _ok, note = seal_readonly(dst)
        dest_paths.append(dst)
        # manifest entry uses verified dst hash
        manifest_entries.append({
            "src": src,
            "dst_file": dest_name,
            "sha512": dst_hex or src_hex,
            "readonly_note": note,
        })
        # quick check chmod stuck
        if readonly and note:
            print("[warn] %s chmod ignored (filesystem may not support permissions)" % dst, file=sys.stderr)

    if with_manifest and manifest_entries:
        # SHA512SUMS — fail-fast if cannot write (ENOSPC etc.)
        sha_path = os.path.join(dest_dir, "SHA512SUMS")
        if os.path.lexists(sha_path) and os.path.isdir(sha_path):
            raise SystemExit("[fatal] cannot write SHA512SUMS (is directory): %s" % sha_path)
        if os.path.exists(sha_path):
            clear_immutable(sha_path)
        try:
            with open(sha_path, "w") as f:
                for e in manifest_entries:
                    f.write("%s  %s\n" % (e["sha512"], e["dst_file"]))
        except OSError as exc:  # noqa: BLE001
            raise SystemExit("[fatal] cannot write SHA512SUMS (%s)" % exc)
        # manifest.json — privacy: store only dst_file+sha512, not absolute src
        man_path = os.path.join(dest_dir, "manifest.json")
        if os.path.lexists(man_path) and os.path.isdir(man_path):
            raise SystemExit("[fatal] cannot write manifest.json (is directory): %s" % man_path)
        if os.path.exists(man_path):
            clear_immutable(man_path)
        try:
            # redact absolute src paths: keep only basename for privacy
            safe_entries = [{"dst_file": e["dst_file"], "sha512": e["sha512"]} for e in manifest_entries]
            manifest = {
                "version": APP_VERSION,
                "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "lock_dir": os.path.basename(os.path.abspath(dest_dir)),
                "files": safe_entries,
                "count": len(safe_entries),
                "readonly": readonly,
                "note": "Locked PASS photos — read-only copies. Re-derive with: photo2seed --no-mix-rng <lock_dir> (if created with --no-mix-rng) or photo2seed <lock_dir> (if CSPRNG-mixed, QR+password is backup).",
            }
            with open(man_path, "w") as f:
                json.dump(manifest, f, indent=2)
        except OSError as exc:  # noqa: BLE001
            raise SystemExit("[fatal] cannot write manifest.json (%s)" % exc)

    return dest_paths, os.path.abspath(dest_dir)


def find_temp_photo_folders():
    """Search system temp and macOS /var for photo2seed temp folders.

    Returns sorted list of (path, file_count, total_bytes).
    Searches: /tmp (realpath), tempfile.gettempdir() (often /var/folders/.../T), $TMPDIR, /var/folders (limited).
    Matches prefix photo2seed-.
    """
    raw_roots = set()
    try:
        raw_roots.add(os.path.abspath(get_system_temp_dir()))
    except Exception:  # noqa: BLE001
        pass
    try:
        raw_roots.add(os.path.abspath(tempfile.gettempdir()))
    except Exception:  # noqa: BLE001
        pass
    tmpdir_env = os.environ.get("TMPDIR", "").strip()
    if tmpdir_env:
        try:
            raw_roots.add(os.path.abspath(tmpdir_env.rstrip("/")))
        except Exception:  # noqa: BLE001
            pass
    # include /var/folders as extra root on macOS to catch legacy dirs
    if sys.platform == "darwin" and os.path.isdir("/var/folders"):
        raw_roots.add(os.path.abspath("/var/folders"))
    if os.path.isdir("/private/tmp"):
        raw_roots.add(os.path.abspath("/private/tmp"))
    # dedup via realpath (handles /tmp -> /private/tmp)
    roots = set()
    for r in raw_roots:
        if not r or not os.path.isdir(r):
            continue
        try:
            roots.add(os.path.realpath(r))
        except Exception:  # noqa: BLE001
            roots.add(r)

    candidates = {}
    for root in sorted(roots):
        if not os.path.isdir(root):
            continue
        # use realpath for root comparison
        real_root = os.path.realpath(root)
        for dirpath, dirnames, filenames in os.walk(real_root, topdown=True, onerror=lambda e: None, followlinks=False):
            # limit depth for /var/folders to avoid huge scan
            if os.path.basename(real_root) == "folders" and "var" in real_root:
                # real_root is /private/var/folders or /var/folders
                depth = dirpath[len(real_root):].count(os.sep)
                if depth > 4:
                    dirnames[:] = []
                    continue
                # prune branches that cannot contain photo2seed- without T
                # keep walk simple but skip obvious non-T at depth 1-2 quickly
                # not pruning aggressively to keep correctness
            base = os.path.basename(dirpath)
            if base.startswith("photo2seed-"):
                real_path = os.path.realpath(dirpath)
                if real_path not in candidates:
                    try:
                        total = 0
                        count = 0
                        for dp, _, fns in os.walk(dirpath, followlinks=False):
                            for fn in fns:
                                fp = os.path.join(dp, fn)
                                try:
                                    total += os.path.getsize(fp)
                                    count += 1
                                except OSError:
                                    pass
                        candidates[real_path] = (count, total)
                    except Exception:  # noqa: BLE001
                        candidates[real_path] = (0, 0)
                    dirnames[:] = []
                    continue

    result = []
    for p in sorted(candidates.keys()):
        c, t = candidates[p]
        result.append((p, c, t))
    return result


def cmd_purge_temp(force=False):
    """Find and optionally purge temp photo folders, with confirmation."""
    folders = find_temp_photo_folders()
    if not folders:
        print("No photo2seed temp folders found in:")
        for r in sorted({os.path.realpath(get_system_temp_dir()), os.path.realpath(tempfile.gettempdir()), os.path.realpath(os.environ.get("TMPDIR","").strip()) if os.environ.get("TMPDIR","").strip() else ""}):
            if r:
                print("  %s" % r)
        if sys.platform == "darwin":
            print("  /var/folders (scanned limited depth, realpath /private/var/folders)")
        return
    print("Found %d photo2seed temp folder(s):" % len(folders))
    for p, cnt, tot in folders:
        print("  %-60s %3d files  %6.1f MB" % (p, cnt, tot / (1024 * 1024)))
    if not force:
        try:
            resp = input("Purge these folders? [y/N] ")
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            return
        if resp.strip().lower() not in ("y", "yes"):
            print("Aborted.")
            return
    # purge — batch clear immutable where possible
    failed = []
    for p, _, _ in folders:
        try:
            # batch clear immutable (darwin/linux) once per folder
            if sys.platform == "darwin":
                subprocess.run(["chflags", "-R", "nouchg", p], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            elif sys.platform.startswith("linux"):
                subprocess.run(["chattr", "-R", "-i", p], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            # fallback per-file clear + chmod for stubborn cases / FAT
            for dirpath, dirnames, filenames in os.walk(p, topdown=False, followlinks=False):
                for fn in filenames:
                    fp = os.path.join(dirpath, fn)
                    # already batch-cleared, just ensure writable
                    try:
                        os.chmod(fp, 0o644)
                    except OSError:
                        pass
                for dn in dirnames:
                    dp = os.path.join(dirpath, dn)
                    try:
                        os.chmod(dp, 0o755)
                    except OSError:
                        pass
            try:
                os.chmod(p, 0o755)
            except OSError:
                pass
            shutil.rmtree(p)
            print("Purged: %s" % p)
        except Exception as exc:  # noqa: BLE001
            print("[warn] failed to purge %s (%s)" % (p, exc), file=sys.stderr)
            failed.append(p)
    if failed:
        print("[warn] %d folder(s) failed to purge" % len(failed), file=sys.stderr)
    else:
        print("Done.")


PICSUM_URL = "https://picsum.photos/{w}/{h}?v={nonce}"


def download_random_photos(count, out_dir, width=2000, height=1500, max_bytes=10 * 1024 * 1024):
    """Download `count` random Picsum photos (JPEG) into `out_dir`.

    Each request appends a unique nonce to bust the redirect/image cache, so a
    fresh random picture is fetched every time. Returns the list of saved paths
    (missing any that failed). Caps read to max_bytes to avoid OOM.
    """
    saved = []
    for i in range(count):
        url = PICSUM_URL.format(w=width, h=height, nonce=time.time_ns())
        dest = os.path.join(out_dir, "random_%02d.jpg" % (i + 1))
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "photo2seed"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                if resp.status != 200 or not resp.headers.get("Content-Type", "").startswith("image/"):
                    raise OSError("unexpected response: %s" % resp.status)
                # cap size to avoid decompression bomb / OOM
                data = resp.read(max_bytes + 1)
            if not data:
                raise OSError("empty body")
            if len(data) > max_bytes:
                raise OSError("response too large (%d > %d)" % (len(data), max_bytes))
            with open(dest, "wb") as f:
                f.write(data)
            print("  downloaded %-30s (%d KB)" % (os.path.basename(dest), len(data) // 1024))
            saved.append(dest)
        except Exception as exc:  # noqa: BLE001 - a failed download should not kill the run
            print("[warn] download %d failed (%s); skipping" % (i + 1, exc), file=sys.stderr)
    return saved


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
  photo2seed --download-random                 fetch 10 random photos to /tmp, derive + QR (stored in system /tmp, not /var/folders)
  photo2seed a.jpg some/dir/ --words 24        24-word seed
  photo2seed photos/ --show-words              also print words/entropy/hashes
  photo2seed photos/ --xfp                     also show master-key fingerprint (XFP)
  photo2seed photos/ --derive-only --xfp       show ONLY the XFP (no words, no KEF)
  photo2seed photos/ --lock                    archive PASS photos to ./<word>-<word>/ read-only
  photo2seed photos/ --lock-dir ./my-lock      archive PASS photos to ./my-lock/ read-only
  photo2seed --purge-temp                      find temp photo2seed folders in /tmp and /var/folders and purge with confirmation
  photo2seed purge --yes                       same as --purge-temp --yes
  photo2seed install                           add 'photo2seed' to your user bin dir
  photo2seed uninstall                         remove the 'photo2seed' launcher

KEF (v20 AES-GCM QR) output is ALWAYS the default. The KEF password is the
only secret protecting the QR - use a long random password.
Photo lock (--lock / --lock-dir) copies every PASS photo byte-identical into
a folder, seals it read-only (0444, uchg/+i where supported), and writes
SHA512SUMS + manifest.json so the folder re-derives deterministically with
--no-mix-rng.
Temp handling: all temp folders use system temp /tmp (not /var/folders); --purge-temp scans /tmp, $TMPDIR and /var/folders for photo2seed- folders.

GitHub: %s
""" % GITHUB_URL


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("install", "uninstall"):
        (cmd_install if sys.argv[1] == "install" else cmd_uninstall)()
        return
    if len(sys.argv) > 1 and sys.argv[1] in ("purge", "purge-temp", "clean-temp"):
        # don't swallow --help
        if "--help" in sys.argv or "-h" in sys.argv:
            pass  # fall through to argparse help
        else:
            force = "--force" in sys.argv or "--yes" in sys.argv or "-y" in sys.argv
            cmd_purge_temp(force=force)
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
    ap.add_argument("paths", nargs="*", help="photo files and/or directories (optional if --download-random)")
    ap.add_argument(
        "--download-random",
        nargs="?",
        type=int,
        const=10,
        default=None,
        metavar="N",
        help="fetch N random photos (default 10, max 10) to a fresh temp dir "
        "in /tmp and use them as photo source; requires network",
    )
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
    ap.add_argument(
        "--lock",
        action="store_true",
        help="archive PASS photos to a new memorable two-word folder (e.g. perch-dog) in cwd, sealed read-only (0444)",
    )
    ap.add_argument(
        "--lock-dir",
        default=None,
        metavar="DIR",
        help="archive PASS photos to DIR (existing or new), sealed read-only; mutually exclusive with --lock",
    )
    ap.add_argument(
        "--no-readonly",
        action="store_true",
        help="when archiving with --lock/--lock-dir, keep copies writable (do not chmod 444)",
    )
    ap.add_argument(
        "--no-manifest",
        action="store_true",
        help="when archiving, skip SHA512SUMS and manifest.json",
    )
    ap.add_argument(
        "--purge-temp",
        action="store_true",
        help="find temp folders (photo2seed- in /tmp and /var/folders) and offer to purge with confirmation",
    )
    ap.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="with --purge-temp, purge without confirmation",
    )
    args = ap.parse_args()

    if args.purge_temp:
        cmd_purge_temp(force=args.yes or args.force)
        return

    validate_iterations(args.iterations)
    if not 0 <= args.min_entropy <= 8:
        raise SystemExit("[fatal] --min-entropy must be between 0 and 8")
    if not 0 <= args.min_brightness <= 255:
        raise SystemExit("[fatal] --min-brightness must be between 0 and 255")
    if args.label is not None and len(args.label) > 20:
        raise SystemExit("[fatal] --label must be 20 characters or fewer")
    if (args.no_readonly or args.no_manifest) and not (args.lock or args.lock_dir):
        print("[warn] --no-readonly/--no-manifest without --lock/--lock-dir has no effect", file=sys.stderr)

    download_count = args.download_random
    if download_count is not None:
        if not 1 <= download_count <= 10:
            raise SystemExit("[fatal] --download-random must be between 1 and 10")
        if args.no_mix_rng:
            raise SystemExit(
                "[fatal] --download-random downloads PUBLIC photos; anyone "
                "fetching the same picture would reproduce the seed under "
                "--no-mix-rng. Remove --no-mix-rng (CSPRNG mixing is required)."
            )
    if not args.paths and download_count is None:
        raise SystemExit(
            "[fatal] no photo source: pass photo paths and/or --download-random"
        )

    load_wordlist(resource_path("english.txt"))

    args.id = args.id or ("kef-photo-" + os.urandom(6).hex())

    if not args.derive_only and os.path.exists(args.out) and not args.force:
        raise SystemExit(
            "[fatal] output file %s already exists (use --force to overwrite)" % args.out
        )

    # early lock validation before expensive work / password prompt
    early_lock_dir = resolve_lock_dir(args.lock, args.lock_dir)
    if early_lock_dir is not None:
        if os.path.lexists(early_lock_dir) and not os.path.isdir(early_lock_dir):
            raise SystemExit("[fatal] --lock-dir exists and is not a directory: %s" % early_lock_dir)
        # reject lock_dir being inside any source path (would cause recursion next run)
        abs_lock = os.path.abspath(early_lock_dir)
        for src_p in args.paths:
            if src_p and _is_subpath(abs_lock, os.path.abspath(src_p)):
                raise SystemExit("[fatal] --lock-dir %s is inside source %s — would be re-collected next run" % (abs_lock, src_p))
        # probe writability early (before password) without creating final lock dir if no PASS
        try:
            parent = os.path.dirname(abs_lock) or "."
            if not os.path.isdir(parent):
                raise OSError("parent not a directory: %s" % parent)
            # check parent writable by probing parent, not creating empty lock dir
            probe = os.path.join(parent, ".photo2seed_probe_%d" % (time.time_ns() % 1000000))
            with open(probe, "w") as f:
                f.write("probe")
            os.remove(probe)
        except OSError as exc:  # noqa: BLE001
            raise SystemExit("[fatal] lock dir not writable %s (%s)" % (abs_lock, exc))
        if not args.derive_only and _is_subpath(os.path.abspath(args.out), abs_lock):
            print("[warn] --out %s is inside lock dir %s — QR will be inside lock and excluded from future collects" % (args.out, abs_lock), file=sys.stderr)

    tmp_download_dir = None
    if download_count is not None:
        tmp_download_dir = tempfile.mkdtemp(prefix="photo2seed-", dir=get_system_temp_dir())
        print("\n== Downloading %d random photos to %s ==" % (download_count, tmp_download_dir))
        download_random_photos(download_count, tmp_download_dir)

    raw_photos = collect_photos(list(args.paths) + ([tmp_download_dir] if tmp_download_dir else []))
    # exclude output QR and lock dir from being re-collected as photos
    _exclude_roots = []
    if not args.derive_only:
        _exclude_roots.append(os.path.abspath(args.out))
    if early_lock_dir is not None:
        _exclude_roots.append(os.path.abspath(early_lock_dir))
    if tmp_download_dir is not None:
        # keep tmp for entropy but mark for lock exclusion later
        pass
    photos = []
    for p in raw_photos:
        ap = os.path.abspath(p)
        skip = False
        for ex in _exclude_roots:
            if ap == ex or _is_subpath(ap, ex):
                skip = True
                break
            # also exclude file == out path exactly
            if ap == ex:
                skip = True
                break
        # skip QR / manifest files that may live inside lock
        if not skip and os.path.basename(p).lower() in ("sha512sums", "manifest.json"):
            # only skip if inside lock_dir
            if early_lock_dir is not None and _is_subpath(ap, os.path.abspath(early_lock_dir)):
                skip = True
        if not skip:
            photos.append(p)
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
        print(
            "\n[error] No usable photo: every photo was rejected by the Shannon "
            "quality check.\n"
            "Seed generation STOPPED - nothing was derived and no QR was "
            "written.\n"
            "This holds even with CSPRNG mixing: photo2seed never generates a "
            "seed without at least one accepted photo.\n"
            "Use high-detail original photos (not flat/dark/re-compressed), or "
            "lower --min-entropy / --min-brightness.",
            file=sys.stderr,
        )
        sys.exit(2)

    total_bytes = 0
    for p in accepted:
        try:
            total_bytes += os.path.getsize(p)
        except OSError:  # noqa: BLE001 - file deleted between Shannon and sizing
            pass
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

    # --- Photo lock: archive PASS photos read-only (before final so digests reusable) ---
    # reuse early validation; early_lock_dir already probed before password
    lock_dir = early_lock_dir
    if lock_dir is not None:
        # exclude downloaded public photos from deterministic lock
        lock_accepted = accepted
        if tmp_download_dir is not None:
            tmp_abs = os.path.abspath(tmp_download_dir)
            filtered = [p for p in accepted if not _is_subpath(os.path.abspath(p), tmp_abs)]
            if len(filtered) != len(accepted):
                print("[warn] --download-random photos are public and excluded from lock (CSPRNG protects seed)" , file=sys.stderr)
            lock_accepted = filtered
            if not lock_accepted:
                print("[warn] no private PASS photos to lock after excluding --download-random", file=sys.stderr)
        if lock_accepted:
            digests_by_path = {p: d.hex() for p, d in entries if p in set(lock_accepted)}
            # ensure digests for filtered still available
            for p in lock_accepted:
                if p not in digests_by_path:
                    digests_by_path[p] = sha512_file(p).hex()
            readonly = not args.no_readonly
            with_manifest = not args.no_manifest
            print("\n== Photo lock ==")
            print("  Lock dir: %s" % os.path.abspath(lock_dir))
            if not args.no_mix_rng:
                print("  [warn] CSPRNG mixing is ON: lock copies alone are NOT sufficient for re-derive; keep QR+password as backup (use --no-mix-rng for deterministic lock)" , file=sys.stderr)
            # fail-fast: any lock error aborts before seed derivation is considered reproducible
            dest_paths, abs_lock = archive_pass_photos(
                lock_accepted, digests_by_path, lock_dir, readonly=readonly, with_manifest=with_manifest
            )
            print("  Archived %d PASS photo(s) -> %s" % (len(dest_paths), abs_lock))
            if readonly:
                print("  Sealed read-only (0444, uchg/+i where supported)")
            else:
                print("  Kept writable (--no-readonly)")
            if with_manifest:
                print("  Manifest: SHA512SUMS + manifest.json")
            if args.no_mix_rng:
                print("  Re-derive deterministically: photo2seed --no-mix-rng --show-words \"%s\"" % abs_lock)
            else:
                print("  Re-derive deterministically only if created with --no-mix-rng; otherwise QR+password is backup: photo2seed --show-words \"%s\" (will derive different words)" % abs_lock)

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
    if tmp_download_dir:
        print(
            "\nDownloaded photos kept in: %s\n"
            "(random public images - the seed is protected by CSPRNG mixing, "
            "not by these photos; delete the folder if you prefer)" % tmp_download_dir
        )


if __name__ == "__main__":
    main()
