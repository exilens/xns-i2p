# xns-i2p

`xns-i2p` converts between XNS Ed25519 owner keys and the extended base32
addresses used by I2P encrypted LeaseSet2 destinations. It also turns an
OpenSSL Ed25519 PKCS#8 private key into a native i2pd destination key file.

## Build

```sh
go build -o xns-i2p ./cmd/xns-i2p
```

## Public key and I2P address

Convert an XNS owner key to its I2P address:

```sh
xns-i2p address 20a16b378779e6f6cd8c7d694e22577a1abf03867a9b8b990a8b5720ebeb511d
```

Extract the XNS owner key from an extended I2P address:

```sh
xns-i2p owner ADDRESS.b32.i2p
```

These are extended base32 addresses for encrypted LeaseSet2 destinations,
not the ordinary base32 hash of a complete I2P Destination.

## OpenSSL private key to i2pd service

Generate an Ed25519 private key:

```sh
openssl genpkey -algorithm Ed25519 -out service.pem
```

Create the i2pd service files:

```sh
xns-i2p service service.pem service
```

The directory contains:

```text
hostname
private.dat
```

Existing files are never overwritten. The directory is mode `0700` and each
file is mode `0600`.

Configure an i2pd HTTP server tunnel using the generated key file:

```ini
[xns-service]
type = http
host = 127.0.0.1
port = 8080
keys = /path/to/service/private.dat
i2cp.leaseSetType = 5
```

The application listening on `127.0.0.1:8080` should accept the claimed XNS
hostname in its HTTP `Host` header.

Inspect and verify a generated service:

```sh
xns-i2p inspect service
```

## Deterministic derivation

An I2P Destination needs both a signing key and an encryption key. The
OpenSSL Ed25519 seed is stored unchanged as the i2pd signing secret. The
X25519 encryption secret and identity padding are derived with HMAC-SHA256.

The derivation is:

```text
encryption_key = HMAC-SHA256(ed25519_seed, "XNS" || 0x00)
identity_pad   = HMAC-SHA256(ed25519_seed, "XNS" || 0x01)
```

The same PEM therefore reproduces the same complete `private.dat`. The XNS
owner key and extended address depend only on the Ed25519 public key.
