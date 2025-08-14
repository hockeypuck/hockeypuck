[![Build Status](https://travis-ci.org/hockeypuck/openpgp.svg?branch=master)](https://travis-ci.org/hockeypuck/openpgp)
[![GoDoc](https://godoc.org/gopkg.in/hockeypuck/openpgp.v0?status.svg)](https://godoc.org/gopkg.in/hockeypuck/openpgp.v0)

# openpgp

Package `openpgp` provides OpenPGP packet processing for keyservers. It is
intended to support verification of signed key material and certifications.

## Purpose

Public keyservers are intended to be beneficial directory service, but in the
OpenPGP cryptosystem, they are not intended to be securely reliable authorities
on the authenticity of keys. Rather, they are tasked with propagating key
material -- good, bad or ugly -- for OpenPGP agents like GnuPG to determine
authenticity and acceptable content.

This package supports the unique concerns of a keyserver, which is not (and
probably should not be) addressed in a typical OpenPGP implementation oriented toward user agents.

## Features

* Merging packets among two certificates.
* De-duplication or preservation of redundant packets in a certificate.
* Resolve revocations, expirations and certifying self-signatures for
  non-authoritative purposes.
* Tolerance and classification of experimental, new, and outdated key material
  for interoperability.
* Certificate digest calculation method compatible with SKS.
* Hierarchical entity modeling of certificate packets.
* Unique scoped identifiers for all packets.
* Reversed-hex key IDs support prefix matching, optimal for many database indexes.

## Usage

This package is newly API versioned by gopkg.in. Expect a v1 branch once it stabilizes.

```go
import "github.com/hockeypuck/openpgp.v0"
```

## License

AGPLv3. Copyright (c) 2015 Casey Marshall.

