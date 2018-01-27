module Data.Digest.Sha1
  ( sha1
  ) where

import Data.ByteString.Lazy (ByteString)

import Data.Digest.Internal

foreign import ccall "openssl/digest.h EVP_sha1" evpSha1 :: Algo

sha1 :: ByteString -> Digest
sha1 = hash evpSha1
