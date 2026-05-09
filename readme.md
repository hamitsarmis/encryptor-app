# encryptor-app

A small Java CLI for encrypting and decrypting strings or files using the Triple DES (DESede) algorithm, backed by BouncyCastle.

## Requirements

- Java 17+
- Maven 3.6+

## Build

```bash
mvn clean package
```

The runnable classes land under `target/classes`.

## Run

```bash
mvn exec:java -Dexec.mainClass=com.tripledesencryptor.app.App
```

Or, after building:

```bash
java -cp target/classes:$(mvn -q dependency:build-classpath -Dmdep.outputFile=/dev/stdout) \
     com.tripledesencryptor.app.App
```

## Usage

On startup the app prints a menu:

```
Usage:
1. String encryption & decryption
2. File encryption
3. File decryption
```

### 1. String encryption / decryption

```
> 1
1. encrypt or 2. decrypt ?
> 1
word?
> hello world
Pass?
> my-secret
Encryption Result: 8mPxK0tQ...
Decryption Result: hello world
```

### 2. File encryption

```
> 2
Path to read?
> ./plain.txt
Path to write?
> ./cipher.bin
Pass?
> my-secret
```

### 3. File decryption

```
> 3
Path to read?
> ./cipher.bin
Path to write?
> ./plain.txt
Pass?
> my-secret
```

Press anything other than `1`, `2`, or `3` at the menu to exit.

## How it works

- The password is hashed with MD5 to produce a 16-byte key.
- The key is used with the `DESede` cipher (Triple DES) via the BouncyCastle JCE provider.
- String input/output uses `IBM1026` encoding; ciphertext is Base64-encoded for the string mode.

## Project layout

```
src/main/java/com/tripledesencryptor/app/
  App.java                 # CLI entry point
  EncryptionManager.java   # encrypt / decrypt helpers
src/test/java/...          # JUnit tests
```

## Dependencies

- `commons-codec`
- `org.bouncycastle:bcprov-jdk18on`
- `junit-jupiter` (test)

## Disclaimer

Triple DES with an MD5-derived key and ECB mode is **not** suitable for new security-critical applications. This project is for learning and demonstration. For production use, prefer AES-GCM with a properly derived key (PBKDF2/Argon2/scrypt).
