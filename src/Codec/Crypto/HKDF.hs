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
    hkdf, HKDFParams(..)
  , extract, ExtractParams(..)
  , expand, ExpandParams(..)

    -- * Cryptographic hash algorithms
  , Algorithm
  , sha1

    -- ** SHA-2 family
    -- | The SHA-2 family of hash functions is defined in
    -- [FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final).
  , sha224, sha256, sha384, sha512

    -- * Error handling
  , Error

    -- * Legacy functions
  , md5
  ) where

import Control.Monad ((>=>))
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Except (runExceptT)
import Data.ByteString (ByteString)
import Foreign (allocaArray)
import Foreign.Marshal.Unsafe (unsafeLocalState)

import BTLS.BoringSSL.Digest (evpMaxMDSize)
import BTLS.BoringSSL.HKDF
import BTLS.Buffer (onBufferOfMaxSize', packCUStringLen)
import BTLS.Result (Error, check)
import BTLS.Types (Algorithm(Algorithm))
import Data.Digest (md5, sha1, sha224, sha256, sha384, sha512)

-- | Computes an HKDF. It is defined as the composition of 'extract' and
-- 'expand' but may be faster than calling the two functions individually.
hkdf :: HKDFParams -> ByteString -> Either [Error] ByteString
hkdf (HKDFParams md salt info outLen) =
  extract (ExtractParams md salt) >=> expand (ExpandParams md info outLen)

data HKDFParams = HKDFParams
  { algorithm :: Algorithm
  , salt :: ByteString
  , associatedData :: ByteString
  , secretLen :: Int
  } deriving (Eq, Show)

-- | Computes an HKDF pseudorandom key (PRK).
extract :: ExtractParams -> ByteString -> Either [Error] ByteString
extract (ExtractParams (Algorithm md) salt) secret =
  unsafeLocalState $
    onBufferOfMaxSize' evpMaxMDSize $ \pOutKey pOutLen ->
      check $ hkdfExtract pOutKey pOutLen md secret salt

data ExtractParams = ExtractParams
  { extractAlgorithm :: Algorithm
  , extractSalt :: ByteString
  } deriving (Eq, Show)

-- | Computes HKDF output key material (OKM).
expand :: ExpandParams -> ByteString -> Either [Error] ByteString
expand (ExpandParams (Algorithm md) info outLen) secret =
  unsafeLocalState $
    allocaArray outLen $ \pOutKey -> runExceptT $ do
      check $ hkdfExpand pOutKey outLen md secret info
      lift $ packCUStringLen (pOutKey, outLen)

data ExpandParams = ExpandParams
  { expandAlgorithm :: Algorithm
  , expandAssociatedData :: ByteString
  , expandSecretLen :: Int
  } deriving (Eq, Show)
