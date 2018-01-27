{-# LANGUAGE CApiFFI #-}
{-# OPTIONS_GHC -Wno-missing-methods #-}

module Data.Digest.Sha1
  ( sha1
  ) where

import Data.ByteString.Lazy (ByteString)
import Foreign (Ptr, Storable(alignment, sizeOf))
import Foreign.C.Types

import Data.Digest.Internal

#include <openssl/sha.h>

data ShaCtx

instance Storable ShaCtx where
  sizeOf _ = #size SHA_CTX
  alignment _ = #alignment SHA_CTX

foreign import capi "openssl/sha.h value SHA_DIGEST_LENGTH"
  shaDigestLength :: CSize

foreign import ccall "openssl/sha.h SHA1_Init"
  sha1Init :: Ptr ShaCtx -> IO CInt

foreign import ccall "openssl/sha.h SHA1_Update"
  sha1Update :: Ptr ShaCtx -> Ptr a -> CSize -> IO CInt

foreign import ccall "openssl/sha.h SHA1_Final"
  sha1Final :: Ptr CUChar -> Ptr ShaCtx -> IO CInt

sha1Algo :: Algo
sha1Algo = Algo shaDigestLength sha1Init sha1Update sha1Final

sha1 :: ByteString -> Digest
sha1 = hash sha1Algo
