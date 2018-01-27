module Data.Digest.Sha2
  ( sha224
  , sha256
  , sha384
  , sha512
  ) where

import Data.ByteString.Lazy (ByteString)

import Data.Digest.Internal

foreign import ccall "openssl/digest.h EVP_sha224" evpSha224 :: Algo

foreign import ccall "openssl/digest.h EVP_sha256" evpSha256 :: Algo

foreign import ccall "openssl/digest.h EVP_sha384" evpSha384 :: Algo

foreign import ccall "openssl/digest.h EVP_sha512" evpSha512 :: Algo

sha224 :: ByteString -> Digest
sha224 = hash evpSha224

sha256 :: ByteString -> Digest
sha256 = hash evpSha256

sha384 :: ByteString -> Digest
sha384 = hash evpSha384

sha512 :: ByteString -> Digest
sha512 = hash evpSha512
