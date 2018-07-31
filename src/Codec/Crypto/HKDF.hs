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

module Codec.Crypto.HKDF
  ( Salt(Salt), SecretKey(SecretKey)
  , extract
  ) where

import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Unsafe as ByteString
import Foreign (Ptr, Storable(peek), alloca, allocaArray)
import Foreign.C.Types
import Foreign.Marshal.Unsafe (unsafeLocalState)
import Unsafe.Coerce (unsafeCoerce)

import Data.Digest.Internal (Algorithm(Algorithm))
import Internal.Digest (evpMaxMDSize)
import Internal.HKDF
import Types (Salt(Salt), SecretKey(SecretKey))

-- | Computes an HKDF pseudorandom key (PRK) as specified by RFC 5869.
extract :: Algorithm -> Salt -> SecretKey -> SecretKey
extract (Algorithm md) (Salt salt) (SecretKey secret) =
  unsafeLocalState $
    allocaArray evpMaxMDSize $ \pOutKey ->
      alloca $ \pOutLen -> do
        -- @HKDF_extract@ won't mutate @secret@ or @salt@, so the sharing inherent
        -- in 'ByteString.unsafeUseAsCStringLen' is fine.
        ByteString.unsafeUseAsCStringLen secret $ \(pSecret, secretLen) ->
          ByteString.unsafeUseAsCStringLen salt $ \(pSalt, saltLen) ->
            hkdfExtract
              (asCUCharBuf pOutKey) pOutLen
              md
              (asCUCharBuf pSecret) (fromIntegral secretLen)
              (asCUCharBuf pSalt) (fromIntegral saltLen)
        outLen <- fromIntegral <$> peek pOutLen
        SecretKey <$> ByteString.packCStringLen (pOutKey, outLen)
  where
    asCUCharBuf :: Ptr CChar -> Ptr CUChar
    asCUCharBuf = unsafeCoerce
