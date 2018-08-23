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
  , hkdf, extract, expand
  ) where

import Foreign (allocaArray)
import Foreign.Marshal.Unsafe (unsafeLocalState)

import BTLS.BoringSSL.Digest (evpMaxMDSize)
import BTLS.BoringSSL.HKDF
import BTLS.BoringSSLPatterns (onBufferOfMaxSize)
import BTLS.Buffer (packCUStringLen, unsafeUseAsCUStringLen)
import BTLS.Types
  ( Algorithm(Algorithm), AssociatedData(AssociatedData), Salt(Salt)
  , SecretKey(SecretKey), noSalt
  )

-- | Computes an HKDF as specified by RFC 5869.
hkdf :: Algorithm -> Salt -> AssociatedData -> Int -> SecretKey -> SecretKey
hkdf md salt info outLen = expand md info outLen . extract md salt

-- | Computes an HKDF pseudorandom key (PRK) as specified by RFC 5869.
extract :: Algorithm -> Salt -> SecretKey -> SecretKey
extract (Algorithm md) (Salt salt) (SecretKey secret) =
  SecretKey $
    unsafeLocalState $
      onBufferOfMaxSize evpMaxMDSize $ \pOutKey pOutLen -> do
        -- @HKDF_extract@ won't mutate @secret@ or @salt@, so the sharing inherent
        -- in 'unsafeUseAsCUStringLen' is fine.
        unsafeUseAsCUStringLen secret $ \(pSecret, secretLen) ->
          unsafeUseAsCUStringLen salt $ \(pSalt, saltLen) ->
            hkdfExtract pOutKey pOutLen md pSecret secretLen pSalt saltLen

-- | Computes HKDF output key material (OKM) as specified by RFC 5869.
expand :: Algorithm -> AssociatedData -> Int -> SecretKey -> SecretKey
expand (Algorithm md) (AssociatedData info) outLen (SecretKey secret) =
  SecretKey $
    unsafeLocalState $
      allocaArray outLen $ \pOutKey -> do
        -- @HKDF_expand@ won't mutate @secret@ or @info@, so the sharing inherent
        -- in 'unsafeUseAsCUStringLen' is fine.
        unsafeUseAsCUStringLen secret $ \(pSecret, secretLen) ->
          unsafeUseAsCUStringLen info $ \(pInfo, infoLen) ->
            hkdfExpand pOutKey (fromIntegral outLen) md pSecret secretLen pInfo infoLen
        packCUStringLen (pOutKey, outLen)
