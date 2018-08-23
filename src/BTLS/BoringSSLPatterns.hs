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
  ( initUpdateFinalize
  , onBufferOfMaxSize
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as ByteString.Lazy
import Foreign (ForeignPtr, Storable(peek), Ptr, alloca, allocaArray, withForeignPtr)
import Foreign.C.Types

import BTLS.BoringSSL.Digest (evpMaxMDSize)
import BTLS.Buffer (packCUStringLen, unsafeUseAsCUStringLen)

type LazyByteString = ByteString.Lazy.ByteString

-- | Encapsulates a common pattern of operation between hashing and HMAC
-- computation. Both of these operations require an allocated context local to
-- the operation. The context gets initialized once, updated repeatedly, and
-- then finalized. Finally, we read the result out of a buffer produced by the
-- finalizer.
--
-- The updater must not mutate any argument other than the context.
--
-- If all arguments are safe to use under 'unsafeLocalState', this whole
-- function is safe to use under 'unsafeLocalState'.
initUpdateFinalize ::
     IO (ForeignPtr ctx)
  -> (Ptr ctx -> IO ())
  -> (Ptr ctx -> Ptr CUChar -> CULong -> IO ())
  -> (Ptr ctx -> Ptr CUChar -> Ptr CUInt -> IO ())
  -> LazyByteString
  -> IO ByteString
initUpdateFinalize mallocCtx initialize update finalize bytes = do
  ctxFP <- mallocCtx
  withForeignPtr ctxFP $ \ctx -> do
    initialize ctx
    mapM_ (updateBytes ctx) (ByteString.Lazy.toChunks bytes)
    onBufferOfMaxSize evpMaxMDSize (finalize ctx)
  where
    updateBytes ctx chunk =
      -- The updater won't mutate its arguments, so the sharing inherent in
      -- 'unsafeUseAsCUStringLen' is fine.
      unsafeUseAsCUStringLen chunk $ \(buf, len) -> update ctx buf len

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
