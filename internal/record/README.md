<!-- Independent reconstruction and validation by ir_spoof; https://t.me/ir_spoof. -->

# Stream record reconstruction

This package independently implements the stream envelopes recovered from the
Netrix 3.0.1 Linux reference binary. The reference project is
[Karrari-Dev/Netrix-](https://github.com/Karrari-Dev/Netrix-). Attribution to
`ir_spoof` identifies this reconstruction, not authorship of the reference.
Framing recovery and matching public cryptographic vectors do not by themselves
prove interoperability with an authenticated reference-core session.

## Recovered envelopes

All integer prefixes are big endian.

| Wrapper | Envelope | Maximum writer data chunk |
| --- | --- | --- |
| Encrypted | `uint16 body_length`, `12-byte nonce`, `AEAD ciphertext + tag` | 65,504 bytes |
| Padded plaintext | `uint16 data_length`, `uint8 padding_length`, padding, data | 16,353 bytes |
| Compression | `uint32 encoded_data_length`, `uint8 flag`, encoded data | Configured `MaxSize` |

The encrypted plaintext consists of one padding-length byte, random padding,
and data. The length prefix is AEAD associated data. The 12-byte nonce begins
with four zero bytes and ends with a 64-bit counter. Peers use opposite counter
parities, start at zero or one, and increment by two. Readers permit a forward
counter difference up to 1,024, rejecting replay. AES-256-GCM and
ChaCha20-Poly1305 both use a 16-byte authentication tag.

The padded plaintext prefix measures data only. The encrypted prefix measures
the nonce and ciphertext, including the tag. The compression prefix measures
encoded data only, excluding its flag byte. Flag value 1 denotes a compressed
block; flag value 0 denotes literal data. Writers only retain compression
when the result is smaller and the configured minimum size has been reached.

The reference's advertised `snappy` option actually calls
`github.com/klauspost/compress/s2.Encode` and `s2.Decode`, which implement S2
blocks with Snappy extensions. It is not the Snappy framed-stream format.
`lz4` uses an LZ4 framed stream through `pierrec/lz4/v4.Writer`, and `zstd`
uses `klauspost/compress/zstd` `EncodeAll`/`DecodeAll`. Exact library versions
could not be recovered from the stripped reference build.

## Constructor contract

Pass a freshly established 32-byte session key to `NewEncrypted` for every
connection. Reusing a static PSK directly as that key with counters reset to
zero would reuse nonces and is unsafe. Authentication and per-connection key
derivation belong to the caller's handshake. `NewAEAD` allows the caller to
provide an already constructed 12-byte-nonce, 16-byte-tag AEAD.

`Stealth` holds padding bounds and optional timing jitter. Jitter's byte limit
is caller policy; this package does not assume the reference's unrecovered
global threshold. A zero byte limit means no byte threshold. Jitter sleeps
are bounded to 60 seconds. Constructor parameters are independent of the
configuration package so the core can supply verified defaults.

`CompressionOptions.MaxSize` bounds both encoded and decoded data, defaults
to 65,536 bytes, and cannot exceed 1 MiB. The caller must choose a limit that
includes its higher-layer frame overhead. Compressed records are not split
silently, since splitting might change the caller's framing assumptions.
Compression framing is still emitted when `Enabled` is false; the flag is
then zero and the payload is literal. A caller that negotiates no compression
wrapper must leave the connection unwrapped instead.

## Explicit hardening differences

The reconstruction additionally rejects a nonzero four-byte nonce prefix,
wrong counter parity, counter overflow, nonempty records with no data, reserved
compression flag bits, and oversized plaintext writes before compression.
The reference writer emits the accepted nonce invariants, but not all of these
checks are visible in its reader. Decompression is bounded before plaintext
is released. LZ4's library uses a bounded frame-block buffer; Zstd's decoder
has explicit memory and window limits. These checks can reject malformed or
nonstandard traffic that a reference build might accept.

Reads and writes are serialized separately. Short underlying writes are
completed, zero-progress writes fail, and partial-frame EOF is reported as
truncation. Authentication or framing failures are terminal for that stream.
No plaintext from a truncated encrypted record is returned. The package
contains no network discovery, license service, telemetry, or disk cache.

## Evidence and checks

Reference virtual addresses, before the analysis image's relocation offset:

| Function | Address |
| --- | --- |
| Encrypted write/read | `0x7ddee0` / `0x7debc0` |
| Padded write/read | `0x7e0100` / `0x7e05c0` |
| Compression write/read | `0x7b4940` / `0x7b4e20` |
| Compression/decompression dispatch | `0x7b5940` / `0x7b5b40` |
| S2 encode/decode | `0x579fc0` / `0x579e00` |
| Zstd encode/decode | `0x5a8a60` / `0x596180` |
| LZ4 writer construction/write/close/reset | `0x5bda40` / `0x5bde40` / `0x5be800` / `0x5be8c0` |

Tests check independently generated AES-GCM and ChaCha20-Poly1305 vectors,
known literal envelopes and an S2 literal block, fragmented reads, short writes,
truncation, tampering, nonce bounds, compressed expansion bounds, codec frame
magic, simultaneous writes, and close behavior. Run them with:

```sh
go test ./internal/record
go vet ./internal/record
```

Tests use in-memory connections and public zero-key vectors. Production
handshake and reference-peer differential tests require separate validation.
