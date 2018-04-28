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

module Data.Digest.Internal where

import Data.Bits (Bits((.&.)), shiftR)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as ByteString.Lazy
import qualified Data.ByteString.Unsafe as ByteString
import Data.Char (intToDigit)
import Data.Word (Word8)
import Foreign
       (FinalizerPtr, ForeignPtr, Ptr, Storable(peek), addForeignPtrFinalizer,
        alloca, allocaArray, mallocForeignPtr, withForeignPtr)
import Foreign.C.Types
import Foreign.Marshal.Unsafe (unsafeLocalState)
import Unsafe.Coerce (unsafeCoerce)

{#import Internal.Base#}
{#import Internal.Digest#} ()
import Foreign.Ptr.Cast (asVoidPtr)
import Result

type LazyByteString = ByteString.Lazy.ByteString

#include <openssl/digest.h>

-- First, we build basic bindings to the BoringSSL EVP interface.

-- Imported functions from BoringSSL. See
-- https://commondatastorage.googleapis.com/chromium-boringssl-docs/digest.h.html
-- for documentation.

evpMaxMdSize :: Int
evpMaxMdSize = {#const EVP_MAX_MD_SIZE#}

-- Some of these functions return 'CInt' even though they can never fail. Wrap
-- them to prevent warnings.

evpDigestUpdate :: Ptr EvpMdCtx -> Ptr a -> CULong -> IO ()
evpDigestUpdate ctx md bytes =
  alwaysSucceeds $ {#call EVP_DigestUpdate as ^#} ctx (asVoidPtr md) bytes

evpDigestFinalEx :: Ptr EvpMdCtx -> Ptr CUChar -> Ptr CUInt -> IO ()
evpDigestFinalEx ctx mdOut outSize =
  alwaysSucceeds $ {#call EVP_DigestFinal_ex as ^#} ctx mdOut outSize

-- Convert functions that can in fact fail to throw exceptions instead.

evpDigestInitEx :: Ptr EvpMdCtx -> Ptr EvpMd -> Ptr Engine -> IO ()
evpDigestInitEx ctx md engine =
  requireSuccess $ {#call EVP_DigestInit_ex as ^#} ctx md engine

-- Now we can build a memory-safe allocator.

-- | Memory-safe allocator for 'EvpMdCtx'.
mallocEvpMdCtx :: IO (ForeignPtr EvpMdCtx)
mallocEvpMdCtx = do
  fp <- mallocForeignPtr
  withForeignPtr fp {#call EVP_MD_CTX_init as ^#}
  addForeignPtrFinalizer btlsFinalizeEvpMdCtxPtr fp
  return fp

foreign import ccall "&btlsFinalizeEvpMdCtx"
  btlsFinalizeEvpMdCtxPtr :: FinalizerPtr EvpMdCtx

-- Finally, we're ready to actually implement the hashing interface.

-- | A cryptographic hash function.
newtype Algorithm = Algorithm (Ptr EvpMd)

-- | The result of a hash operation.
newtype Digest =
  Digest ByteString
  deriving (Eq, Ord)

instance Show Digest where
  show (Digest d) = ByteString.foldr showHexPadded [] d
    where
      showHexPadded b xs =
        hexit (b `shiftR` 4 .&. 0x0f) : hexit (b .&. 0x0f) : xs
      hexit = intToDigit . fromIntegral :: Word8 -> Char

-- | Hashes according to the given 'Algorithm'.
hash :: Algorithm -> LazyByteString -> Digest
hash (Algorithm md) bytes =
  unsafeLocalState $ do
    ctxFP <- mallocEvpMdCtx
    withForeignPtr ctxFP $ \ctx -> do
      evpDigestInitEx ctx md noEngine
      mapM_ (updateBytes ctx) (ByteString.Lazy.toChunks bytes)
      d <-
        allocaArray evpMaxMdSize $ \mdOut ->
          alloca $ \pOutSize -> do
            evpDigestFinalEx ctx mdOut pOutSize
            outSize <- fromIntegral <$> peek pOutSize
            -- 'mdOut' is a 'Ptr CUChar'. However, to make life more
            -- interesting, 'CString' is a 'Ptr CChar', and 'CChar' is signed.
            -- This is especially unfortunate given that all we really want to
            -- do is convert to a 'ByteString', which is unsigned. To work
            -- around it, we're going to cheat and let Haskell reinterpret-cast
            -- 'mdOut' to 'Ptr CChar' before it does its 'ByteString' ingestion.
            ByteString.packCStringLen (unsafeCoerce mdOut, outSize)
      return (Digest d)
  where
    updateBytes ctx chunk =
      -- 'mdUpdate' treats its @buf@ argument as @const@, so the sharing
      -- inherent in 'ByteString.unsafeUseAsCStringLen' is fine.
      ByteString.unsafeUseAsCStringLen chunk $ \(buf, len) ->
        evpDigestUpdate ctx buf (fromIntegral len)
