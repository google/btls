-- Copyright 2017 Google LLC
--
-- Licensed under the Apache License, Version 2.0 (the "License"); you may not
-- use this file except in compliance with the License. You may obtain a copy of
-- the License at
--
--     https://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
-- WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
-- License for the specific language governing permissions and limitations under
-- the License.

{-|
  Module: Data.Digest
  Description: Cryptographic hash functions
  Copyright: 2017 Google LLC
  License: Apache License, version 2.0

  Cryptographic hash functions.
-}
module Data.Digest
  ( -- * Computing digests
    Digest
  , hash

    -- * Digest algorithms
  , Algorithm

    -- ** SHA-2 family
    -- | The SHA-2 family of hash functions is defined in
    -- [FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final).
  , sha224, sha256, sha384, sha512

    -- * Legacy functions
  , md5
  , sha1
  ) where

import qualified Data.ByteString.Lazy as Lazy (ByteString)
import qualified Data.ByteString.Lazy as ByteString.Lazy
import Foreign.Marshal.Unsafe (unsafeLocalState)

import BTLS.BoringSSL.Base
import BTLS.BoringSSL.Digest
import BTLS.Buffer (onBufferOfMaxSize)
import BTLS.Types (Algorithm(Algorithm), Digest(Digest))

-- | Message Digest 5, a 128-bit digest defined in
-- [RFC 1321](https://tools.ietf.org/html/rfc1321). This algorithm is
-- cryptographically broken; do not use it except to interface with legacy
-- applications.
md5 :: Algorithm
md5 = Algorithm evpMD5

-- | Secure Hash Algorithm 1, a 160-bit digest defined in
-- [FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final).
-- Hashing with this algorithm is cryptographically broken, although
-- constructing HMACs with it is safe.
sha1 :: Algorithm
sha1 = Algorithm evpSHA1

-- | The SHA224 digest, a 224-bit digest and Secure Hash Algorithm 2 family
-- member.
sha224 :: Algorithm
sha224 = Algorithm evpSHA224

-- | The SHA256 digest, a 256-bit digest and Secure Hash Algorithm 2 family
-- member. Prefer this algorithm on 32-bit CPUs; it will run faster than
-- 'sha384' or 'sha512'.
sha256 :: Algorithm
sha256 = Algorithm evpSHA256

-- | The SHA384 digest, a 384-bit digest and Secure Hash Algorithm 2 family
-- member.
sha384 :: Algorithm
sha384 = Algorithm evpSHA384

-- | The SHA512 digest, a 512-bit digest and Secure Hash Algorithm 2 family
-- member. Prefer this algorithm on 64-bit CPUs; it will run faster than
-- 'sha224' or 'sha256'.
sha512 :: Algorithm
sha512 = Algorithm evpSHA512

-- | Hashes according to the given 'Algorithm'.
hash :: Algorithm -> Lazy.ByteString -> Digest
hash (Algorithm md) bytes =
  unsafeLocalState $ do
    ctx <- mallocEVPMDCtx
    evpDigestInitEx ctx md noEngine
    mapM_ (evpDigestUpdate ctx) (ByteString.Lazy.toChunks bytes)
    Digest <$> onBufferOfMaxSize evpMaxMDSize (evpDigestFinalEx ctx)
