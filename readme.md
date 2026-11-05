# encryptor-app

A Java CLI that encrypts and decrypts strings or files with a password.

The password is stretched with PBKDF2-HMAC-SHA256 (600 000 iterations, random 16-byte salt) into a 256-bit key. The data is encrypted with AES-256-GCM under a fresh random 12-byte IV, which also authenticates it with a 128-bit tag. Salt, IV and ciphertext are stored together, so the password is the only thing needed to decrypt. Everything comes from the JCA providers shipped with the JDK; there are no runtime dependencies.

## Architecture

```
 password ──▶ PBKDF2-HMAC-SHA256 ──▶ 256-bit key ──┐
              600 000 iterations                   │
              salt: 16 random bytes                ▼
 plaintext ──────────────────────────────▶ AES/GCM/NoPadding ──▶ ciphertext + 16-byte tag
                                           iv: 12 random bytes

 output:   salt (16) || iv (12) || ciphertext + tag
           strings: Base64 of those bytes        files: the raw bytes
```

## Components

**`EncryptionManager`** — the whole cryptographic surface: `encrypt` / `decrypt` for byte arrays and for strings, `encryptFile` / `decryptFile` for paths. Decryption throws `AEADBadTagException` when the password is wrong or any byte of salt, IV, ciphertext or tag was changed.

**`App`** — interactive menu around it. Reads from the terminal when one is attached (the password is not echoed), from stdin otherwise.

**`EncryptionManagerTest`** — 12 JUnit 5 tests: round trips for strings, bytes and files; a flipped byte in each of salt, IV, ciphertext and tag; wrong password; fresh salt and IV per message; output layout; and a vector produced by an independent implementation (Python `hashlib` + `cryptography`).

## Quick start

Needs Java 17+ and Maven 3.6+.

```bash
mvn clean package                                    # compiles and runs the tests
java -cp target/classes com.tripledesencryptor.app.App
```

The menu asks for the password first, then for the input:

```
Usage:
1. String encryption & decryption
2. File encryption
3. File decryption
> 1
Pass?
> my-secret
1. encrypt or 2. decrypt ?
> 1
word?
> hello world
Encryption Result: 0MnA/XaVjHdRpy8U71wdxYXb/3niZoE4rSygDpW7Uo8goSYqU7nxv8am0mKkA8AyDW8E0pE1nw==
Decryption Result: hello world
```

Options `2` and `3` ask for `Path to read?` and `Path to write?`. Any other menu input exits. The Base64 string is different on every run because salt and IV are random.

## Configuration

There are no settings. The parameters are constants in `EncryptionManager`:

| Constant | Purpose | Value |
|---|---|---|
| `PBKDF2_ITERATIONS` | PBKDF2-HMAC-SHA256 rounds | `600000` |
| `KEY_LENGTH_BITS` | AES key size | `256` |
| `SALT_LENGTH` | random salt per message, bytes | `16` |
| `IV_LENGTH` | random GCM IV per message, bytes | `12` |
| `TAG_LENGTH_BITS` | GCM authentication tag | `128` |

## Design decisions

- **Why AES-GCM replaced 3DES.** The first version hashed the password once with MD5 and ran two-key Triple DES in ECB mode: no salt and no IV, so equal passwords gave equal keys and equal plaintext blocks gave equal ciphertext blocks.
  It had no integrity check either; a modified ciphertext decrypted to garbage without an error, where GCM now refuses with `AEADBadTagException`.
  Triple DES itself has a 64-bit block and NIST no longer allows it for new encryption (SP 800-131A Rev. 2).
- **PBKDF2 at 600 000 iterations.** Why: it is in every JDK, and 600 000 is the OWASP minimum for PBKDF2-HMAC-SHA256. Trade-off: every encrypt and every decrypt pays for a full key derivation, and PBKDF2 is not memory-hard the way Argon2 or scrypt are.
- **Salt and IV travel with the ciphertext.** Why: only the password is needed to decrypt, and a new salt per message means the same password never produces the same key twice. Trade-off: 44 bytes of overhead on every message.
- **The tag is checked before anything is written.** `decryptFile` creates the output file only after the whole input has been authenticated. Trade-off: the file is processed in memory in one piece.
- **JDK providers only.** BouncyCastle and commons-codec are gone; Base64 is `java.util.Base64`. Trade-off: no algorithms beyond what the JDK ships.

## Caveats

- Not compatible with the Triple DES version. Data encrypted before this change can only be decrypted with the old code, commit `ca9422a`.
- Files are read into memory completely. The limit is the JVM heap, and 2 GB at most.
- Strings are encoded as UTF-8. The old version used IBM1026.
- The password is a Java `String`, so it cannot be wiped from memory after use. When stdin is not a terminal it is read as an ordinary line.
- The Java package is still called `com.tripledesencryptor.app`. Only the name is left of Triple DES.
- The code has not been audited. Use it to learn from, not to protect something that matters.
