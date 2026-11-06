#!/usr/bin/env python3
"""Encrypt a file for the Secrets page.

The file's SHA-256 digest is the key material:
  - the digest doubles as the integrity check (the decrypted+decompressed
    content must hash back to it)
  - a derived key encrypts with a SHA256-CTR keystream (stdlib only)
  - the digest is Base91-encoded with the site's unambiguous alphabet as the
    user-facing key; output files are named after its first 4 + last 2 chars

Usage:
  python encrypt.py <file>                  single segment
  python encrypt.py <file> --size=<size>    segments of <size> (K/M/G, e.g. 10M)
  python encrypt.py <file> --name=<name>    custom embedded file name
  python encrypt.py <file> --no-name        store no file name (leading \\0)
  python encrypt.py <file> --no-compress    skip zlib compression
  python encrypt.py <file> --key-only       just print the key, write nothing

Segment layout (integers big-endian, header travels as plaintext; segment
indices are 0-based everywhere, filenames use 4 lowercase hex digits):
  seg_count (2B)                                     always
  index (1B; 2B when seg_count > 255)                only when seg_count > 1
  total_size (8B)                                    only in segment 0: size of
                                                    the decrypted+decompressed
                                                    file content
  cipher_size (4B)                                   this segment's cipher bytes
  cipher (cipher_size bytes)

Output files are named <tag><index-as-4-hex>.enc, e.g. tag.abc -> abc0000.enc.

Concatenating every segment's cipher and XOR-decrypting yields:
  flag (1B)    0 = stored, 1 = zlib-compressed
  data         the (optionally compressed) inner stream

The inner stream (after decompression when flag = 1) is:
  name \\0      the file name; a leading \\0 means "no name"
  content      the file body; SHA-256(content) must equal the key digest
"""
import hashlib
import os
import re
import sys
import zlib

ALPHABET = ''.join(chr(c) for c in range(0x21, 0x7F) if chr(c) not in '0Il')
BLOCK = 32  # SHA-256 output size

# Filename tag escaping: 30 chars (ASCII order) -> '-' + one of [0-9a-t].
TAG_CHARS = "!\"#$%&'()*+,./:;<=>?@[\\]^`{|}~"
TAG_CODES = '0123456789abcdefghijklmnopqrst'
TAG_MAP = {c: TAG_CODES[i] for i, c in enumerate(TAG_CHARS)}


def safe_tag(s: str) -> str:
    """Escape chars that are illegal/hazardous in URLs and Windows filenames.

    Keeps [A-Za-z0-9_]; every other char becomes '-' + a single code from
    [0-9a-t] (assigned in ASCII order, see TAG_CHARS/TAG_CODES), and '-'
    itself becomes '--'. Dots and tildes are escaped too, so tags never
    contain '.', '~' or a bare '-'. Mirrors safeTag() in src/Secrets/index.js.
    """
    out = []
    for ch in s:
        if ch == '-':
            out.append('--')
        elif ch in TAG_MAP:
            out.append('-' + TAG_MAP[ch])
        else:
            out.append(ch)
    return ''.join(out)


def base91_encode(data: bytes) -> str:
    b = n = 0
    out = []
    for byte in data:
        b |= byte << n
        n += 8
        if n > 13:
            v = b & 8191
            if v > 88:
                b >>= 13
                n -= 13
            else:
                v = b & 16383
                b >>= 14
                n -= 14
            out.append(ALPHABET[v % 91])
            out.append(ALPHABET[v // 91])
    if n:
        out.append(ALPHABET[b % 91])
    if n > 7:
        out.append(ALPHABET[b // 91])
    return ''.join(out)


def keystream_block(enc_key: bytes, counter: int) -> bytes:
    return hashlib.sha256(enc_key + counter.to_bytes(8, 'big')).digest()


def xor_with_keystream(data: bytes, enc_key: bytes) -> bytes:
    out = bytearray()
    counter = 0
    for off in range(0, len(data), BLOCK):
        pad = keystream_block(enc_key, counter)
        counter += 1
        chunk = data[off:off + BLOCK]
        x = int.from_bytes(chunk, 'little') ^ int.from_bytes(pad[:len(chunk)], 'little')
        out += x.to_bytes(len(chunk), 'little')
    return bytes(out)


def parse_size(s: str) -> int:
    """'10M' -> bytes (1024-based K/M/G suffixes; bare digits = bytes)."""
    m = re.fullmatch(r'(\d+)([KMG]?)', s.strip(), re.IGNORECASE)
    if not m:
        raise ValueError(s)
    return int(m.group(1)) * {'': 1, 'K': 1024, 'M': 1024 ** 2, 'G': 1024 ** 3}[m.group(2).upper()]


def main(argv):
    if not argv or argv[0] in ('-h', '--help'):
        print(__doc__)
        return 2
    path = argv[0]
    size_limit = None
    custom_name = None
    no_name = False
    no_compress = False
    key_only = False
    extra = argv[1:]
    i = 0
    while i < len(extra):
        arg = extra[i]
        if arg == '--key-only':
            key_only = True
        elif arg == '--no-name':
            no_name = True
        elif arg == '--no-compress':
            no_compress = True
        elif arg == '--name':
            if i + 1 >= len(extra):
                sys.exit('error: --name requires a value')
            i += 1
            custom_name = extra[i]
        elif arg.startswith('--name='):
            custom_name = arg[len('--name='):]
        elif arg.startswith('--size='):
            try:
                size_limit = parse_size(arg[len('--size='):])
            except ValueError:
                sys.exit(f'error: bad size "{arg[len("--size="):]}"')
        elif arg == '--size':
            sys.exit('error: use --size=<size>, e.g. --size=10M')
        else:
            sys.exit(f'error: unknown argument "{arg}"')
        i += 1
    if custom_name is not None and no_name:
        sys.exit('error: --name and --no-name are mutually exclusive')
    if custom_name is not None and '\x00' in custom_name:
        sys.exit('error: name must not contain NUL bytes')
    if size_limit is not None and size_limit < 1:
        sys.exit('error: --size must be >= 1')

    with open(path, 'rb') as fh:
        data = fh.read()
    digest = hashlib.sha256(data).digest()
    key_b91 = base91_encode(digest)
    if key_only:
        print('key  :', key_b91)
        print('sha256:', digest.hex())
        return 0

    enc_key = hashlib.sha256(b'Secrets/v1' + digest).digest()
    tag = safe_tag(key_b91[:4] + key_b91[-2:])
    directory = os.path.dirname(os.path.abspath(path))

    # Inner stream: name\0 + content (leading \0 = no name).
    name_part = (custom_name if custom_name is not None else os.path.basename(path))
    name_bytes = b'\x00' if no_name else name_part.encode('utf-8') + b'\x00'
    payload = name_bytes + data
    if no_compress:
        flag, body = 0, payload
    else:
        flag, body = 1, zlib.compress(payload, 9)
    cipher = xor_with_keystream(bytes([flag]) + body, enc_key)

    # Split the cipher strictly by --size: every segment but the last gets
    # EXACTLY size_limit cipher bytes (no rounding up to the 32-byte
    # keystream block — segments are concatenated before decryption, so the
    # keystream simply continues across segment boundaries).
    if size_limit is None:
        per, seg_count = len(cipher), 1
    else:
        per = size_limit
        seg_count = max(1, -(-len(cipher) // per))
    if seg_count > 0xFFFF:
        sys.exit(f'error: {seg_count} segments exceed the 65535 limit (raise --size)')
    idx_width = 2 if seg_count > 255 else 1

    names = []
    for k in range(seg_count):
        part = cipher[k * per:(k + 1) * per]
        head = seg_count.to_bytes(2, 'big')
        if seg_count > 1:
            head += k.to_bytes(idx_width, 'big')
        if k == 0:
            head += len(data).to_bytes(8, 'big')
        head += len(part).to_bytes(4, 'big')
        name = f'{tag}{k:04x}.enc'
        with open(os.path.join(directory, name), 'wb') as fh:
            fh.write(head + part)
        names.append(name)

    print('key  :', key_b91)
    print('parts:', seg_count)
    for name in names:
        print('file :', os.path.join(directory, name))
    print('sha256:', digest.hex())
    print('size :', len(data), 'bytes', '(compressed)' if flag else '(stored)')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
