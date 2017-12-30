{-# LANGUAGE CApiFFI #-}
{-# OPTIONS_GHC -Wno-missing-methods #-}

module Data.Digest.Evp
  ( Algo
  , Digest(Digest)
  , hash
  ) where

import Control.Exception (bracket_)
import Control.Monad (void)
import Data.Bits (Bits((.&.)), shiftR)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Unsafe as ByteString
import Data.Char (intToDigit)
import Data.Word (Word8)
import Foreign
       (Ptr, Storable(alignment, peek, sizeOf), alloca, allocaArray,
        nullPtr, throwIf_)
import Foreign.C.Types
import System.IO.Unsafe (unsafePerformIO)
import Unsafe.Coerce (unsafeCoerce)

#include <openssl/digest.h>

-- First, we build basic bindings to the BoringSSL EVP interface.

-- | The BoringSSL @ENGINE@ type.
data Engine

-- | The BoringSSL @EVP_MD@ type, representing a hash algorithm.
data EvpMd

-- | A convenience alias for @Ptr EvpMd@.
type Algo = Ptr EvpMd

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

foreign import ccall "openssl/digest.h EVP_MD_CTX_cleanup"
  evpMdCtxCleanup' :: Ptr EvpMdCtx -> IO CInt

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

evpMdCtxCleanup :: Ptr EvpMdCtx -> IO ()
evpMdCtxCleanup = void . evpMdCtxCleanup'

evpDigestUpdate :: Ptr EvpMdCtx -> Ptr a -> CSize -> IO ()
evpDigestUpdate ctx md bytes = void $ evpDigestUpdate' ctx md bytes

evpDigestFinalEx :: Ptr EvpMdCtx -> Ptr CUChar -> Ptr CUInt -> IO ()
evpDigestFinalEx ctx mdOut outSize = void $ evpDigestFinalEx' ctx mdOut outSize

-- Convert functions that can in fact fail to throw exceptions instead.

evpDigestInitEx :: Ptr EvpMdCtx -> Ptr EvpMd -> Ptr Engine -> IO ()
evpDigestInitEx ctx md engine =
  throwIf_ (/= 1) (const "BoringSSL failure") $ evpDigestInitEx' ctx md engine

-- Now we can build a memory-safe abstraction layer.

-- | Memory-safe wrapper for 'EvpMdCtx'.
withMdCtx :: (Ptr EvpMdCtx -> IO a) -> IO a
withMdCtx f =
  alloca $ \ctx -> bracket_ (evpMdCtxInit ctx) (evpMdCtxCleanup ctx) (f ctx)

-- Finally, we're ready to actually implement the hashing interface.

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

hash :: Algo -> ByteString -> Digest
hash md bytes =
  -- We'd like to use 'unsafeLocalState' (i.e., 'unsafeDupablePerformIO') here,
  -- but 'unsafeDupablePerformIO' runs computation in a context where it can be
  -- arbitrarily terminated--i.e., where the cleanup in 'withMdCtx' is not
  -- guaranteed to run. See
  -- https://hackage.haskell.org/package/base/docs/System-IO-Unsafe.html#v:unsafeDupablePerformIO.
  unsafePerformIO $
  withMdCtx $ \ctx -> do
    evpDigestInitEx ctx md noEngine
    -- evpDigestUpdate treats its @buf@ argument as @const@, so the sharing
    -- inherent in 'ByteString.unsafeUseAsCStringLen' is fine.
    ByteString.unsafeUseAsCStringLen bytes $ \(buf, len) ->
      evpDigestUpdate ctx buf (fromIntegral len)
    d <-
      allocaArray (fromIntegral evpMaxMdSize) $ \mdOut ->
        alloca $ \pOutSize -> do
          evpDigestFinalEx ctx mdOut pOutSize
          outSize <- fromIntegral <$> peek pOutSize
          -- 'mdOut' is a 'Ptr CUChar'. However, to make life more interesting,
          -- 'CString' is a 'Ptr CChar', and 'CChar' is signed. This is
          -- especially unfortunate given that all we really want to do is
          -- convert to a 'ByteString', which is unsigned. To work around it,
          -- we're going to cheat and let Haskell reinterpret-cast 'mdOut' to
          -- 'Ptr CChar' before it does its 'ByteString' ingestion.
          ByteString.packCStringLen (unsafeCoerce mdOut, outSize)
    return (Digest d)
  where
    noEngine = nullPtr :: Ptr Engine
