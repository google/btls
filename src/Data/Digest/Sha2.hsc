{-# LANGUAGE CApiFFI #-}
{-# OPTIONS_GHC -Wno-missing-methods #-}

module Data.Digest.Sha2
  ( sha224
  , sha256
  , sha384
  , sha512
  ) where

import Data.ByteString.Lazy (ByteString)
import Foreign (Ptr, Storable(alignment, sizeOf))
import Foreign.C.Types

import Data.Digest.Internal

#include <openssl/sha.h>

-- SHA-224

foreign import capi "openssl/sha.h value SHA224_DIGEST_LENGTH"
  sha224DigestLength :: CSize

foreign import ccall "openssl/sha.h SHA224_Init"
  sha224Init :: Ptr Sha256Ctx -> IO CInt

foreign import ccall "openssl/sha.h SHA224_Update"
  sha224Update :: Ptr Sha256Ctx -> Ptr a -> CSize -> IO CInt

foreign import ccall "openssl/sha.h SHA224_Final"
  sha224Final :: Ptr CUChar -> Ptr Sha256Ctx -> IO CInt

sha224Algo :: Algo
sha224Algo = Algo sha224DigestLength sha224Init sha224Update sha224Final

sha224 :: ByteString -> Digest
sha224 = hash sha224Algo

-- SHA-256

data Sha256Ctx

instance Storable Sha256Ctx where
  sizeOf _ = #size SHA256_CTX
  alignment _ = #alignment SHA256_CTX

foreign import capi "openssl/sha.h value SHA256_DIGEST_LENGTH"
  sha256DigestLength :: CSize

foreign import ccall "openssl/sha.h SHA256_Init"
  sha256Init :: Ptr Sha256Ctx -> IO CInt

foreign import ccall "openssl/sha.h SHA256_Update"
  sha256Update :: Ptr Sha256Ctx -> Ptr a -> CSize -> IO CInt

foreign import ccall "openssl/sha.h SHA256_Final"
  sha256Final :: Ptr CUChar -> Ptr Sha256Ctx -> IO CInt

sha256Algo :: Algo
sha256Algo = Algo sha256DigestLength sha256Init sha256Update sha256Final

sha256 :: ByteString -> Digest
sha256 = hash sha256Algo

-- SHA-384

foreign import capi "openssl/sha.h value SHA384_DIGEST_LENGTH"
  sha384DigestLength :: CSize

foreign import ccall "openssl/sha.h SHA384_Init"
  sha384Init :: Ptr Sha512Ctx -> IO CInt

foreign import ccall "openssl/sha.h SHA384_Update"
  sha384Update :: Ptr Sha512Ctx -> Ptr a -> CSize -> IO CInt

foreign import ccall "openssl/sha.h SHA384_Final"
  sha384Final :: Ptr CUChar -> Ptr Sha512Ctx -> IO CInt

sha384Algo :: Algo
sha384Algo = Algo sha384DigestLength sha384Init sha384Update sha384Final

sha384 :: ByteString -> Digest
sha384 = hash sha384Algo

-- SHA-512

data Sha512Ctx

instance Storable Sha512Ctx where
  sizeOf _ = #size SHA512_CTX
  alignment _ = #alignment SHA512_CTX

foreign import capi "openssl/sha.h value SHA512_DIGEST_LENGTH"
  sha512DigestLength :: CSize

foreign import ccall "openssl/sha.h SHA512_Init"
  sha512Init :: Ptr Sha512Ctx -> IO CInt

foreign import ccall "openssl/sha.h SHA512_Update"
  sha512Update :: Ptr Sha512Ctx -> Ptr a -> CSize -> IO CInt

foreign import ccall "openssl/sha.h SHA512_Final"
  sha512Final :: Ptr CUChar -> Ptr Sha512Ctx -> IO CInt

sha512Algo :: Algo
sha512Algo = Algo sha512DigestLength sha512Init sha512Update sha512Final

sha512 :: ByteString -> Digest
sha512 = hash sha512Algo
