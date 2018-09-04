-- Copyright 2018 Google LLC
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
  Module: Codec.Crypto.HKDF
  Description: Hash-based key derivation
  Copyright: 2018 Google LLC
  License: Apache License, version 2.0

  The hash-based key derivation function (HKDF), as specified in
  [RFC 5869](https://tools.ietf.org/html/rfc5869).
-}
module Codec.Crypto.HKDF
  ( -- * Computing keys
    SecretKey(SecretKey)
  , hkdf
  , extract
  , expand

    -- * Cryptographic hash algorithms
  , Algorithm
  , sha1

    -- ** SHA-2 family
    -- | The SHA-2 family of hash functions is defined in
    -- [FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final).
  , sha224, sha256, sha384, sha512

    -- * Salt

    -- | You may salt the hash used to generate the key. If you do not wish to
    -- do so, specify 'noSalt' as the salt.
  , Salt(Salt), noSalt

    -- * Associated data
    -- | You may mix in arbitrary data when generating a key. If you do not wish
    -- to do so, specify the empty string as the associated data.
  , AssociatedData(AssociatedData)

    -- * Legacy functions
  , md5
  ) where

import Foreign (allocaArray)
import Foreign.Marshal.Unsafe (unsafeLocalState)

import BTLS.BoringSSL.Digest (evpMaxMDSize)
import BTLS.BoringSSL.HKDF
import BTLS.Buffer (onBufferOfMaxSize, packCUStringLen)
import BTLS.Types
  ( Algorithm(Algorithm), AssociatedData(AssociatedData), Salt(Salt)
  , SecretKey(SecretKey), noSalt
  )
import Data.Digest (md5, sha1, sha224, sha256, sha384, sha512)

-- | Computes an HKDF. It is defined by
--
-- prop> hkdf md salt info len = expand md info len . extract md salt
--
-- but may be faster than calling the two functions individually.
hkdf ::
     Algorithm
  -> Salt
  -> AssociatedData
  -> Int -- ^ The length of the derived key, in bytes.
  -> SecretKey
  -> SecretKey
hkdf md salt info outLen = expand md info outLen . extract md salt

-- | Computes an HKDF pseudorandom key (PRK).
extract :: Algorithm -> Salt -> SecretKey -> SecretKey
extract (Algorithm md) (Salt salt) (SecretKey secret) =
  SecretKey $
    unsafeLocalState $
      onBufferOfMaxSize evpMaxMDSize $ \pOutKey pOutLen -> do
        hkdfExtract pOutKey pOutLen md secret salt

-- | Computes HKDF output key material (OKM).
expand ::
     Algorithm
  -> AssociatedData
  -> Int -- ^ The length of the OKM, in bytes.
  -> SecretKey
  -> SecretKey
expand (Algorithm md) (AssociatedData info) outLen (SecretKey secret) =
  SecretKey $
    unsafeLocalState $
      allocaArray outLen $ \pOutKey -> do
        hkdfExpand pOutKey outLen md secret info
        packCUStringLen (pOutKey, outLen)
