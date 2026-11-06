# Secrets

Serve encrypted resources from any static host. Files are uploaded as opaque
`.enc` segments; visitors paste a key into a web page and the file is
decrypted **in the browser, while it downloads** — appearing in the browser's
download manager exactly like a normal download (native progress, speed and
cancel). No server-side logic, no backend, no accounts.

```
encrypt.py  CLI: encrypt/split any file, prints the Base91 key
web/        the key page (vanilla HTML/CSS/JS + a small service worker)
```

## How it works

- **The key *is* the content hash.** A file's SHA-256 digest is encoded with
  a 91-symbol unambiguous alphabet (printable ASCII minus `0`, `I`, `l`), so a
  32-byte digest is always 40 readable characters. The digest doubles as the
  integrity check — after decryption the page re-hashes the output and
  refuses anything that does not match.
- **Encryption:** SHA256-CTR keystream
  (`block_i = SHA256(SHA256("Secrets/v1" ‖ digest) ‖ counter_be64)`), XOR'd
  over the payload. Pure `hashlib` on the Python side, pure
  `crypto.subtle` in the browser — no crypto libraries.
- **Payload:** optionally zlib-compressed; the original file name travels
  inside the encrypted stream, so downloads restore it automatically.
- **Segments:** the cipher is split into strictly `--size` chunks, each with a
  tiny plaintext header (`seg_count`, `index`, `total_size` in segment 0,
  `cipher_size`). The page fetches exactly `seg_count` files — no probing.
- **Streaming:** fetch → XOR-decrypt → inflate → incremental SHA-256 → the
  download sink, one chunk at a time with backpressure; memory stays bounded
  for arbitrarily large files. Pause/cancel controls included.
- **"Normal" downloads:** a service worker serves the decrypted stream with
  `Content-Disposition` + exact `Content-Length`, so the browser's own
  download UI tracks progress and speed. Falls back to a Blob download when
  service workers are unavailable.

## Usage

```bash
python encrypt.py photo.zip                  # single segment + key
python encrypt.py video.mkv --size=10M       # 10 MiB segments
python encrypt.py doc.pdf --name=手册.pdf     # custom embedded file name
python encrypt.py x.bin --no-name            # name-less resource
python encrypt.py x.bin --no-compress        # store without zlib
python encrypt.py x.bin --key-only           # print the key, write nothing
```

Upload the generated `<tag><hex>.enc` files next to `web/` (default resource
location `<origin>/assets`; override per visit via the location box or
`?location=https://cdn.example/files/`). Share the key with whoever should
have the file — the page does the rest.

## Local development

```bash
npm install
npm start          # http://localhost:8000/Secrets
```

`serve.json` maps `/Secrets/*` to `web/*` and `/assets/*` to `web/assets/*`,
so drop encrypted segments into `web/assets/` and open
<http://localhost:8000/Secrets>. `localhost` is a secure context, so the
service-worker download path works during development.

## Security model

Content is confidential from anyone **without** the key: ciphertext and key
can live on the same public host. There is no authentication, replay
protection or per-user revocation — a shared key can be re-shared. Treat it
as "secret link, but the link is the key", not as access control.

## License

Licensed under the [GNU LGPL v3.0](https://www.gnu.org/licenses/lgpl-3.0.html).
