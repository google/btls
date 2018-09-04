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
  Module: Data.HMAC
  Description: Hash-based message authentication codes
  Copyright: 2018 Google LLC
  License: Apache License, version 2.0

  Hash-based message authentication codes (HMACs). An HMAC guarantees
  authenticity but not confidentiality.
-}
module Data.HMAC
  ( -- * Computing HMACs
    HMAC
  , hmac

    -- * Cryptographic hash algorithms
  , Algorithm
  , sha1

    -- ** SHA-2 family
    -- | The SHA-2 family of hash functions is defined in
    -- [FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final).
  , sha224, sha256, sha384, sha512

    -- * Keys
  , SecretKey(SecretKey)

    -- * Error handling
  , Error

    -- * Legacy functions
  , md5
  ) where

import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Except (runExceptT)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as Lazy (ByteString)
import qualified Data.ByteString.Lazy as ByteString.Lazy
import qualified Data.ByteString.Unsafe as ByteString
import Foreign (withForeignPtr)
import Foreign.Marshal.Unsafe (unsafeLocalState)

import BTLS.BoringSSL.Base
import BTLS.BoringSSL.Digest (evpMaxMDSize)
import BTLS.BoringSSL.HMAC
import BTLS.BoringSSL.Mem (cryptoMemcmp)
import BTLS.Buffer (onBufferOfMaxSize)
import BTLS.Result (Error, check)
import BTLS.Types (Algorithm(Algorithm), Digest(Digest), SecretKey(SecretKey))
import Data.Digest (md5, sha1, sha224, sha256, sha384, sha512)

-- | A hash-based message authentication code. Equality comparisons on this type
-- are constant-time.
newtype HMAC = HMAC ByteString

instance Eq HMAC where
  (HMAC a) == (HMAC b) =
    unsafeLocalState $
      ByteString.unsafeUseAsCStringLen a $ \(a', size) ->
        ByteString.unsafeUseAsCStringLen b $ \(b', _) ->
          (==0) <$> cryptoMemcmp a' b' size

instance Show HMAC where
  show (HMAC m) = show (Digest m)

-- | Creates an HMAC according to the given 'Algorithm'.
hmac :: Algorithm -> SecretKey -> Lazy.ByteString -> Either [Error] HMAC
hmac (Algorithm md) (SecretKey key) bytes =
  unsafeLocalState $ do
    ctxFP <- mallocHMACCtx
    withForeignPtr ctxFP $ \ctx -> runExceptT $ do
      check $ hmacInitEx ctx key md noEngine
      lift $ mapM_ (hmacUpdate ctx) (ByteString.Lazy.toChunks bytes)
      lift $ HMAC <$> onBufferOfMaxSize evpMaxMDSize (hmacFinal ctx)
