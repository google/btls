# btls

btls is a TLS and cryptography library for Haskell. It’s built on top of
[BoringSSL](https://boringssl.googlesource.com/boringssl), Google’s audited fork
of OpenSSL.

Although BoringSSL does not have a stable API or ABI, we expect that btls will
converge to a stable API before we release btls version 1. In the meantime, the
API remains unstable, we do not follow the [Package Versioning
Policy](https://pvp.haskell.org), and we will not post btls on Hackage.

**btls is not production ready yet.** It is feature-incomplete and has not
undergone review or auditing.

---

This is not an official Google product.

This product includes cryptographic software written by [Eric
Young](mailto:eay@cryptsoft.com).

This product includes software written by [Tim
Hudson](mailto:tjh@cryptsoft.com).

This product includes software developed by the OpenSSL Project for use in the
[OpenSSL Toolkit](https://www.openssl.org).
