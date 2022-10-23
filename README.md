# Android TLS Hunter

Detect TLS misconfiguration in Android applications.

Reference: [USENIX'21 Why Eve and Mallory Still Love Android: Revisiting TLS (In)Security in Android Applications](https://www.usenix.org/system/files/sec21-oltrogge.pdf)

## Features

Typical misconfiguration:

* [x] Permits cleartext traffic in `AndroidManifest.xml` (or omitted before Android 9)
* [x] Permits cleartext traffic in network security configuration (a.k.a. NSC)
* [x] Does not pin any certificates in NSC
* [x] User CA store overrides pinned certificates in NSC
* [x] ...

## Usage

```bash
go run ./cmd/tlshunter a.apk b.apk c.apk
# or
go build ./cmd/tlshunter
./tlshunter a.apk b.apk c.apk
```
