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

{-# LANGUAGE CApiFFI #-}
{-# OPTIONS_GHC -Wno-missing-methods #-}

module Data.Digest.Internal where

import Control.Exception (assert)
import Data.Bits (Bits((.&.)), shiftR)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as ByteString.Lazy
import qualified Data.ByteString.Unsafe as ByteString
import Data.Char (intToDigit)
import Data.Word (Word8)
import Foreign
       (FinalizerPtr, ForeignPtr, Ptr, Storable(alignment, peek, sizeOf),
        addForeignPtrFinalizer, alloca, allocaArray, mallocForeignPtr,
        nullPtr, throwIf_, withForeignPtr)
import Foreign.C.Types
import Foreign.Marshal.Unsafe (unsafeLocalState)
import Unsafe.Coerce (unsafeCoerce)

type LazyByteString = ByteString.Lazy.ByteString

#include <openssl/digest.h>

-- First, we build basic bindings to the BoringSSL EVP interface.

-- | The BoringSSL @ENGINE@ type.
data Engine

noEngine :: Ptr Engine
noEngine = nullPtr

-- | The BoringSSL @EVP_MD@ type, representing a hash algorithm.
data EvpMd

-- | The BoringSSL @EVP_MD_CTX@ type, representing the state of a pending
-- hashing operation.
data EvpMdCtx

instance Storable EvpMdCtx where
  sizeOf _ = #size EVP_MD_CTX
  alignment _ = #alignment EVP_MD_CTX

-- Imported functions from BoringSSL. See
-- https://commondatastorage.googleapis.com/chromium-boringssl-docs/digest.h.html
-- for documentation.

foreign import ccall "openssl/digest.h EVP_MD_CTX_init"
  evpMdCtxInit :: Ptr EvpMdCtx -> IO ()

foreign import ccall "openssl/digest.h EVP_DigestInit_ex"
  evpDigestInitEx' :: Ptr EvpMdCtx -> Ptr EvpMd -> Ptr Engine -> IO CInt

foreign import capi "openssl/digest.h value EVP_MAX_MD_SIZE"
  evpMaxMdSize :: CSize

foreign import ccall "openssl/digest.h EVP_DigestUpdate"
  evpDigestUpdate' :: Ptr EvpMdCtx -> Ptr a -> CSize -> IO CInt

foreign import ccall "openssl/digest.h EVP_DigestFinal_ex"
  evpDigestFinalEx' :: Ptr EvpMdCtx -> Ptr CUChar -> Ptr CUInt -> IO CInt

-- Some of these functions return 'CInt' even though they can never fail. Wrap
-- them to prevent warnings.

alwaysSucceeds :: IO CInt -> IO ()
alwaysSucceeds f = do
  r <- f
  assert (r == 1) (return ())

evpDigestUpdate :: Ptr EvpMdCtx -> Ptr a -> CSize -> IO ()
evpDigestUpdate ctx md bytes = alwaysSucceeds $ evpDigestUpdate' ctx md bytes

evpDigestFinalEx :: Ptr EvpMdCtx -> Ptr CUChar -> Ptr CUInt -> IO ()
evpDigestFinalEx ctx mdOut outSize =
  alwaysSucceeds $ evpDigestFinalEx' ctx mdOut outSize

-- Convert functions that can in fact fail to throw exceptions instead.

requireSuccess :: IO CInt -> IO ()
requireSuccess f = throwIf_ (/= 1) (const "BoringSSL failure") f

evpDigestInitEx :: Ptr EvpMdCtx -> Ptr EvpMd -> Ptr Engine -> IO ()
evpDigestInitEx ctx md engine = requireSuccess $ evpDigestInitEx' ctx md engine

-- Now we can build a memory-safe allocator.

-- | Memory-safe allocator for 'EvpMdCtx'.
mallocEvpMdCtx :: IO (ForeignPtr EvpMdCtx)
mallocEvpMdCtx = do
  fp <- mallocForeignPtr
  withForeignPtr fp evpMdCtxInit
  addForeignPtrFinalizer btlsFinalizeEvpMdCtxPtr fp
  return fp

#def void btlsFinalizeEvpMdCtx(EVP_MD_CTX* const ctx) {
  (void)EVP_MD_CTX_cleanup(ctx);
}

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
        allocaArray (fromIntegral evpMaxMdSize) $ \mdOut ->
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
