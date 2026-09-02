# ripemd160.py - pure Python implementation of RIPEMD-160
#
# Based on the public-domain implementation by Bjorn Edstrom <be@bjrn.se>
# (December 2007), itself derived from Markus Friedl's C implementation
# (BSD licensed). Provided for platforms whose OpenSSL build disables the
# RIPEMD-160 legacy provider (common with OpenSSL 3), where hashlib does
# not expose "ripemd160".
#
# RIPEMD-160 reference: Preneel, Bosselaers, Dobbertin, "The Cryptographic
# Hash Function RIPEMD-160" (RSA CryptoBytes, 1997).
#
# Test vectors (verified at import time by _selftest):
#   ""      -> 9c1185a5c5e9fc54612808977ee8f548b2258d31
#   "abc"   -> 8eb208f7e05d987a9b044a8e98c6b087f15a0bfc
#   "a"*1e6 -> 52783243c1697bdbe16d37f97f68f08325dc1528

import struct

_MASK = 0xFFFFFFFF


def _rol(x, n):
    return ((x << n) | (x >> (32 - n))) & _MASK


def _f0(x, y, z):
    return x ^ y ^ z


def _f1(x, y, z):
    return (x & y) | ((x ^ _MASK) & z)


def _f2(x, y, z):
    return (x | (y ^ _MASK)) ^ z


def _f3(x, y, z):
    return (x & z) | (y & (z ^ _MASK))


def _f4(x, y, z):
    return x ^ (y | (z ^ _MASK))


_F = (_f0, _f1, _f2, _f3, _f4)

# round constants, left and right lines
_K = (0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E)
_KK = (0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000)

# message word selection, left (r) and right (r')
_R = (
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
)
_RR = (
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
)
# left rotation amounts, left (s) and right (s')
_S = (
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
)
_SS = (
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
)


def _compress(h, block):
    x = struct.unpack("<16L", block)
    al, bl, cl, dl, el = h
    ar, br, cr, dr, er = h
    for j in range(80):
        fj = j // 16
        t = (al + _F[fj](bl, cl, dl) + x[_R[j]] + _K[fj]) & _MASK
        t = (_rol(t, _S[j]) + el) & _MASK
        al, el, dl, cl, bl = el, dl, _rol(cl, 10), bl, t
        t = (ar + _F[4 - fj](br, cr, dr) + x[_RR[j]] + _KK[fj]) & _MASK
        t = (_rol(t, _SS[j]) + er) & _MASK
        ar, er, dr, cr, br = er, dr, _rol(cr, 10), br, t
    t = (h[1] + cl + dr) & _MASK
    h[1] = (h[2] + dl + er) & _MASK
    h[2] = (h[3] + el + ar) & _MASK
    h[3] = (h[4] + al + br) & _MASK
    h[4] = (h[0] + bl + cr) & _MASK
    h[0] = t
    return h


class Ripemd160:
    digest_size = 20

    def __init__(self, data=b""):
        self._h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
        self._buf = b""
        self._len = 0
        if data:
            self.update(data)

    def update(self, data):
        self._buf += bytes(data)
        self._len += len(data)
        while len(self._buf) >= 64:
            self._h = _compress(self._h, self._buf[:64])
            self._buf = self._buf[64:]
        return self

    def digest(self):
        h = self._h[:]
        length_bits = (self._len << 3) & 0xFFFFFFFFFFFFFFFF
        data = self._buf + b"\x80"
        if len(data) <= 56:
            data = struct.pack("<56sQ", data, length_bits)
        else:
            data = struct.pack("<120sQ", data, length_bits)
        for off in range(0, len(data), 64):
            h = _compress(h, data[off:off + 64])
        return struct.pack("<5L", *h)

    def hexdigest(self):
        return self.digest().hex()


def new(data=b""):
    return Ripemd160(data)


def ripemd160(data):
    return Ripemd160(data).digest()


_VECTORS = (
    (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
    (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
    (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
    (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
    (b"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "12a053384a9c0c88e405a06c27dcf49ada62eb2b"),
    (b"a" * 1000000, "52783243c1697bdbe16d37f97f68f08325dc1528"),
)


def _selftest():
    for data, expect in _VECTORS:
        if ripemd160(data).hex() != expect:
            raise RuntimeError("RIPEMD-160 self-test failed for input of length %d" % len(data))
    return True


_selftest()


if __name__ == "__main__":
    _selftest()
    print("RIPEMD-160 self-test OK (all vectors pass)")
