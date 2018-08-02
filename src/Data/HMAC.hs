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

module Data.HMAC
  ( SecretKey(SecretKey)
  , HMAC
  , hmac
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as ByteString.Lazy
import qualified Data.ByteString.Unsafe as ByteString
import Foreign (Ptr)
import Foreign.C.Types
import Foreign.Marshal.Unsafe (unsafeLocalState)
import Unsafe.Coerce (unsafeCoerce)

import BTLS.BoringSSL.Base
import BTLS.BoringSSL.HMAC
import BTLS.ConstantTimeEquals (constantTimeEquals)
import BTLS.Types (SecretKey(SecretKey))
import Data.Digest.Internal
  (Algorithm(Algorithm), Digest(Digest), initUpdateFinalize)

type LazyByteString = ByteString.Lazy.ByteString

-- | A hash-based message authentication code. Equality comparisons on this type
-- are constant-time.
newtype HMAC = HMAC ByteString

instance Eq HMAC where
  (HMAC a) == (HMAC b) =
    unsafeLocalState $
      ByteString.unsafeUseAsCStringLen a $ \(a', size) ->
        ByteString.unsafeUseAsCStringLen b $ \(b', _) ->
          constantTimeEquals a' b' size

instance Show HMAC where
  show (HMAC m) = show (Digest m)

-- | Creates an HMAC according to the given 'Algorithm'.
hmac :: Algorithm -> SecretKey -> LazyByteString -> HMAC
hmac (Algorithm md) (SecretKey key) =
  HMAC
    . unsafeLocalState
    . initUpdateFinalize mallocHMACCtx initialize update finalize
  where
    initialize ctx =
      ByteString.unsafeUseAsCStringLen key $ \(keyBytes, keySize) ->
        hmacInitEx ctx keyBytes (fromIntegral keySize) md noEngine

    -- initUpdateFinalize deals with buffers that are 'Ptr CChar'. However,
    -- BoringSSL's HMAC functions deal with buffers that are 'Ptr CUChar'. As
    -- in Data.Digest, we'll let Haskell reinterpret-cast the buffers.
    update ctx buf len = hmacUpdate ctx (asCUCharBuf buf) len
    finalize ctx hmacOut pOutSize = hmacFinal ctx (asCUCharBuf hmacOut) pOutSize

    asCUCharBuf :: Ptr CChar -> Ptr CUChar
    asCUCharBuf = unsafeCoerce
