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

## Building

btls includes a copy of BoringSSL as a Git submodule. Ensure you’ve checked out
that submodule before building. If you’ve just cloned btls, `git submodule
update --init` should do it. You’ll also need all of BoringSSL’s build
dependencies. On Debian, run

    apt install cmake gcc g++ golang ninja-build perl

to install them. You do not need to build BoringSSL itself; btls’s Setup.hs will
take care of that for you.

btls needs GHC, c2hs and a few Haskell libraries to build. On Debian,

    apt install c2hs ghc libghc-gtk2hs-buildtools-dev

should get you everything you need; you can also run

    apt install libghc-{base16-bytestring,monad-loops,smallcheck,tasty,tasty-hunit,tasty-smallcheck}-dev

if you want to install everything you can through APT instead of Cabal. Once
you’ve done so, you can build and run the test suite.

    cabal new-build tests
    dist-newstyle/build/btls-*/build/tests/tests

---

This is not an official Google product.

This product includes cryptographic software written by [Eric
Young](mailto:eay@cryptsoft.com).

This product includes software written by [Tim
Hudson](mailto:tjh@cryptsoft.com).

This product includes software developed by the OpenSSL Project for use in the
[OpenSSL Toolkit](https://www.openssl.org).
