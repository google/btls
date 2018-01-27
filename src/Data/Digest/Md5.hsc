{-# LANGUAGE CApiFFI #-}
{-# OPTIONS_GHC -Wno-missing-methods #-}

module Data.Digest.Md5
  ( md5
  ) where

import Data.ByteString.Lazy (ByteString)
import Foreign (Ptr, Storable(alignment, sizeOf))
import Foreign.C.Types

import Data.Digest.Internal

#include <openssl/md5.h>

data Md5Ctx

instance Storable Md5Ctx where
  sizeOf _ = #size MD5_CTX
  alignment _ = #alignment MD5_CTX

foreign import capi "openssl/md5.h value MD5_DIGEST_LENGTH"
  md5DigestLength :: CSize

foreign import ccall "openssl/md5.h MD5_Init"
  md5Init :: Ptr Md5Ctx -> IO CInt

foreign import ccall "openssl/md5.h MD5_Update"
  md5Update :: Ptr Md5Ctx -> Ptr a -> CSize -> IO CInt

foreign import ccall "openssl/md5.h MD5_Final"
  md5Final :: Ptr CUChar -> Ptr Md5Ctx -> IO CInt

md5Algo :: Algo
md5Algo = Algo md5DigestLength md5Init md5Update md5Final

md5 :: ByteString -> Digest
md5 = hash md5Algo
