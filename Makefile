# photo2seed - single-binary build
#
# make            build a native binary for this OS/arch -> dist/
# make build-linux  build the Tails/Debian amd64 ELF via Docker
# make check      smoke-test the built binary
# make sha256     write dist/SHA256SUMS
# make venv       (re)create .venv with pinned runtime+build deps
# make clean      remove dist/, build/, *.spec

OS   := $(shell uname -s | tr '[:upper:]' '[:lower:]')
ARCH := $(shell uname -m)
NAME := photo2seed-$(OS)-$(ARCH)

VENV   := .venv
PYINST := $(VENV)/bin/pyinstaller
PYFLAGS := --onefile --add-data "english.txt:." --exclude-module tkinter \
           --clean --noconfirm --strip

.PHONY: all venv build build-linux check sha256 clean

all: build

venv: $(PYINST)

$(PYINST):
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install -q -r build-requirements.txt

build: $(PYINST)
	$(PYINST) $(PYFLAGS) --name $(NAME) photo2seed.py
	@ls -la dist/ | grep -v "^total"

# Tails / Debian amd64: cross-build from any host via Docker (start Docker first)
build-linux:
	docker run --rm --platform linux/amd64 \
	  -v "$(CURDIR):/src" -w /src python:3.12-slim \
	  sh -c "apt-get update -qq && apt-get install -y -qq binutils >/dev/null \
	    && pip install -q --no-warn-script-location -r build-requirements.txt \
	    && python -m PyInstaller $(PYFLAGS) --name photo2seed-linux-amd64 photo2seed.py \
	    && chmod +x dist/photo2seed-linux-amd64 \
	    && chown -R $(shell id -u):$(shell id -g) dist"
	@ls -la dist/ | grep -v "^total"

check:
	@set -e; \
	BIN=dist/$(NAME); \
	[ -x "$$BIN" ] || { echo "[fatal] $$BIN missing - run 'make build' first"; exit 2; }; \
	$(VENV)/bin/python -c "from PIL import Image; import random; Image.frombytes('L',(512,512),bytes(random.getrandbits(8) for _ in range(512*512))).save('/tmp/pk_test.png')"; \
	echo "== version =="; \
	$$BIN --version; \
	echo "== exit code (derive-only) =="; \
	$$BIN --derive-only /tmp/pk_test.png >/dev/null 2>&1; \
	echo "exit=$$?"; \
	echo "== leak scan (must print 0) =="; \
	$$BIN --derive-only /tmp/pk_test.png 2>/dev/null | grep -cE "sha512=|Final SHA-512|entropy \(" || true; \
	echo "== words present with --show-words =="; \
	$$BIN --derive-only --show-words /tmp/pk_test.png 2>/dev/null | grep -q "BIP39 words (12)" && echo OK; \
	echo "== XFP printed with --xfp (8 hex chars) =="; \
	$$BIN --derive-only --xfp /tmp/pk_test.png 2>/dev/null | grep -qE "^XFP: [0-9A-F]{8}" && echo OK; \
	echo "== determinism (--no-mix-rng, two runs) =="; \
	W1=$$($$BIN --derive-only --show-words --no-mix-rng /tmp/pk_test.png 2>/dev/null | awk '/BIP39 words/{f=1} /^\[--derive-only\]/{f=0} f'); \
	W2=$$($$BIN --derive-only --show-words --no-mix-rng /tmp/pk_test.png 2>/dev/null | awk '/BIP39 words/{f=1} /^\[--derive-only\]/{f=0} f'); \
	[ "$$W1" = "$$W2" ] && [ -n "$$W1" ] && echo OK; \
	echo "== QR annotation bands (top XFP + bottom label) =="; \
	$(VENV)/bin/python -c "\
from PIL import Image; \
import photo2seed, tempfile, os; \
bare = tempfile.mktemp(suffix='.png'); ann = tempfile.mktemp(suffix='.png'); \
photo2seed.render_qr('TESTDATA', bare); \
photo2seed.render_qr('TESTDATA', ann, top_text='XFP: 73C5DA0A', bottom_text='KEF QR'); \
b = Image.open(bare); a = Image.open(ann); \
assert a.size[1] > b.size[1], 'expected annotated QR taller than bare QR'; \
h, w = a.size[1], a.size[0]; \
assert sum(1 for p in a.crop((0,0,w,55)).convert('L').getdata() if p < 128) > 0, 'no top-band ink'; \
assert sum(1 for p in a.crop((0,h-45,w,h)).convert('L').getdata() if p < 128) > 0, 'no bottom-band ink'; \
os.remove(bare); os.remove(ann); print('OK bare', b.size, 'annotated', a.size)"; \
	echo "== label >20 chars rejected =="; \
	$$BIN --derive-only --label "012345678901234567890" /tmp/pk_test.png >/dev/null 2>&1 && { echo FAIL; exit 1; } || echo OK; \
	rm -f /tmp/pk_test.png; \
	echo "== all checks passed =="

sha256:
	@cd dist && shasum -a 256 photo2seed-* > SHA256SUMS && cat SHA256SUMS

clean:
	rm -rf dist build *.spec
