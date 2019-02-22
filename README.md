# tfs_lib

TFS Lib is a collection of assorted utilities useful for embedded or contained application programming.  It currently supports Android, iOS, Linux, and MacOS/Darwin. Portions of this code have been used on ESP8266 microcontroller.

Specific capabilities include:

* TLS and crypto abstraction layer that can interchangeably use Apple CommonCrypto, BoringSSL, or MBedTLS
* Carry-in crypto implementations of AES128, ChaCha20, Ed25519, ECC, RSA, SHA1, SHA256, SHA512, MD5
* PCKS7 signature and X509 certificate parsing
* A speciality implementation to load and process a database/collection of strings, signatures, and hash lookups
* Utilities to walk Linux process list via /proc/ and parse memory map in /proc/self/maps
* An HTTP/HTTPS client with particular support for certificate pinning and extra certificate verification hooks
* Network utilities like a URL parser and DNS lookup
* A general persistent storage layer, using speciality capabilities of Android and iOS, that includes integrity protection of the data at rest
* A file-backed memory queue that includes integrity protection and encryption
* A speciality TLV parser that includes optional integrity protection and encryption
* Utility functions like Base64, CRC, random
* A carry-in copy of AOSP libzip, for zip file parsing


All of the implemented functionality has very specific properties, by design:

* Deterministic/static memory use; no use of malloc() or dynamic allocation anywhere except in RSA encryption and Zip parsing code
* Significant attention to integrity protection and other application fortification design principles; this code has been used within mobile security products
* Most strings are intentionally obfuscated
* Specifically built to use TFS Libc, which can bundle a limited libc implementation and reduce any external imports; this limits ability to hook or tamper the library operation


## Development Notes

There are a few nuances that make this library atypical to work with:

* There are things done specifically for security obfuscation purposes
* It goes to great lengths to not use dynamic memory allocation, and keep memory consumption appropriate for constrained devices like ESP8266 microcontrollers
* API definitions and usage patterns were co-developed for very specific use cases, and not necessarily designed for general-purpose use

This library also requires:

* TFS Libc: https://github.com/j-forristal/tfs_libc



# License

A majority of this code is written in 2019 by Jeff Forristal, jeff@forristal.com

To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring rights to this software to the public domain worldwide. This software is distributed without any warranty.

Please see LICENSE file for a copy of the CC0 Public Domain Dedication.

A certain portion of code included is written by third parties.  Please see the NOTICES file for the licenses of third-party code included in this collection.
