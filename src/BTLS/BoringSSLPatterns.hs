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

module BTLS.BoringSSLPatterns
  ( onBufferOfMaxSize
  ) where

import Data.ByteString (ByteString)
import Foreign (Storable(peek), Ptr, alloca, allocaArray)
import Foreign.C.Types

import BTLS.Buffer (packCUStringLen)

-- | Allocates a buffer, runs a function 'f' to partially fill it, and packs the
-- filled data into a 'ByteString'. 'f' must write the size of the filled data,
-- in bytes and not including any trailing null, into its second argument.
--
-- If 'f' is safe to use under 'unsafeLocalState', this whole function is safe
-- to use under 'unsafeLocalState'.
onBufferOfMaxSize ::
     (Integral size, Storable size)
  => Int
  -> (Ptr CUChar -> Ptr size -> IO ())
  -> IO ByteString
onBufferOfMaxSize maxSize f =
  allocaArray maxSize $ \pOut ->
    alloca $ \pOutLen -> do
      f pOut pOutLen
      outLen <- peek pOutLen
      packCUStringLen (pOut, outLen)
