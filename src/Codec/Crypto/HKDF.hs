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
  ( AssociatedData(AssociatedData), Salt(Salt), SecretKey(SecretKey), noSalt
  , extract, expand
  ) where

import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Unsafe as ByteString
import Foreign (Storable(peek), alloca, allocaArray)
import Foreign.Marshal.Unsafe (unsafeLocalState)

import BTLS.BoringSSL.Digest (evpMaxMDSize)
import BTLS.BoringSSL.HKDF
import BTLS.Cast (asCUCharBuf)
import BTLS.Types
  ( Algorithm(Algorithm), AssociatedData(AssociatedData), Salt(Salt)
  , SecretKey(SecretKey), noSalt
  )

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

-- | Computes HKDF output key material (OKM) as specified by RFC 5869.
expand :: Algorithm -> AssociatedData -> Int -> SecretKey -> SecretKey
expand (Algorithm md) (AssociatedData info) outLen (SecretKey secret) =
  unsafeLocalState $
    allocaArray outLen $ \pOutKey -> do
      -- @HKDF_expand@ won't mutate @secret@ or @info@, so the sharing inherent
      -- in 'ByteString.unsafeUseAsCStringLen' is fine.
      ByteString.unsafeUseAsCStringLen secret $ \(pSecret, secretLen) ->
        ByteString.unsafeUseAsCStringLen info $ \(pInfo, infoLen) ->
          hkdfExpand
            (asCUCharBuf pOutKey) (fromIntegral outLen)
            md
            (asCUCharBuf pSecret) (fromIntegral secretLen)
            (asCUCharBuf pInfo) (fromIntegral infoLen)
      SecretKey <$> ByteString.packCStringLen (pOutKey, outLen)
