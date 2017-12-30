module Data.Digest.Sha2
  ( sha224
  , sha256
  , sha384
  , sha512
  ) where

import Data.ByteString (ByteString)

import qualified Data.Digest.Evp as Evp

foreign import ccall "openssl/digest.h EVP_sha224" evpSha224 :: Evp.Algo

foreign import ccall "openssl/digest.h EVP_sha256" evpSha256 :: Evp.Algo

foreign import ccall "openssl/digest.h EVP_sha384" evpSha384 :: Evp.Algo

foreign import ccall "openssl/digest.h EVP_sha512" evpSha512 :: Evp.Algo

sha224 :: ByteString -> Evp.Digest
sha224 = Evp.hash evpSha224

sha256 :: ByteString -> Evp.Digest
sha256 = Evp.hash evpSha256

sha384 :: ByteString -> Evp.Digest
sha384 = Evp.hash evpSha384

sha512 :: ByteString -> Evp.Digest
sha512 = Evp.hash evpSha512
