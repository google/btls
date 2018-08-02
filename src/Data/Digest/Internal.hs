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

module Data.Digest.Internal
  ( Algorithm(..)
  , Digest(..)
  , initUpdateFinalize
  ) where

import Data.Bits (Bits((.&.)), shiftR)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Unsafe as ByteString
import qualified Data.ByteString.Lazy as ByteString.Lazy
import Data.Char (intToDigit)
import Data.Word (Word8)
import Foreign (ForeignPtr, Storable(peek), Ptr, alloca, allocaArray, withForeignPtr)
import Foreign.C.Types

import BTLS.BoringSSL.Base (EVPMD)
import BTLS.BoringSSL.Digest (evpMaxMDSize)

type LazyByteString = ByteString.Lazy.ByteString

-- | A cryptographic hash function.
newtype Algorithm = Algorithm (Ptr EVPMD)

-- | The result of a hash operation.
newtype Digest = Digest ByteString
  deriving (Eq, Ord)

instance Show Digest where
  show (Digest d) = ByteString.foldr showHexPadded [] d
    where
      showHexPadded b xs =
        hexit (b `shiftR` 4 .&. 0x0f) : hexit (b .&. 0x0f) : xs
      hexit = intToDigit . fromIntegral :: Word8 -> Char

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
  -> (Ptr ctx -> Ptr CChar -> CULong -> IO ())
  -> (Ptr ctx -> Ptr CChar -> Ptr CUInt -> IO ())
  -> LazyByteString
  -> IO ByteString
initUpdateFinalize mallocCtx initialize update finalize bytes = do
  ctxFP <- mallocCtx
  withForeignPtr ctxFP $ \ctx -> do
    initialize ctx
    mapM_ (updateBytes ctx) (ByteString.Lazy.toChunks bytes)
    allocaArray evpMaxMDSize $ \rOut ->
      alloca $ \pOutSize -> do
        finalize ctx rOut pOutSize
        outSize <- fromIntegral <$> peek pOutSize
        ByteString.packCStringLen (rOut, outSize)
  where
    updateBytes ctx chunk =
      -- The updater won't mutate its arguments, so the sharing inherent in
      -- 'ByteString.unsafeUseAsCStringLen' is fine.
      ByteString.unsafeUseAsCStringLen chunk $ \(buf, len) ->
        update ctx buf (fromIntegral len)
