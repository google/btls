module Data.Digest.Md5
  ( md5
  ) where

import Data.ByteString.Lazy (ByteString)

import Data.Digest.Internal

foreign import ccall "openssl/digest.h EVP_md5" evpMd5 :: Algo

md5 :: ByteString -> Digest
md5 = hash evpMd5
