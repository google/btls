module Data.Digest
  ( Algorithm
  , Digest
  , hash
  , md5
  , sha1
  , sha224
  , sha256
  , sha384
  , sha512
  ) where

import Foreign (Ptr)

import Data.Digest.Internal


foreign import ccall "openssl/digest.h EVP_md5" evpMd5 :: Ptr EvpMd

md5 :: Algorithm
md5 = Algorithm evpMd5


foreign import ccall "openssl/digest.h EVP_sha1" evpSha1 :: Ptr EvpMd

sha1 :: Algorithm
sha1 = Algorithm evpSha1


foreign import ccall "openssl/digest.h EVP_sha224" evpSha224 :: Ptr EvpMd

foreign import ccall "openssl/digest.h EVP_sha256" evpSha256 :: Ptr EvpMd

foreign import ccall "openssl/digest.h EVP_sha384" evpSha384 :: Ptr EvpMd

foreign import ccall "openssl/digest.h EVP_sha512" evpSha512 :: Ptr EvpMd

sha224 :: Algorithm
sha224 = Algorithm evpSha224

sha256 :: Algorithm
sha256 = Algorithm evpSha256

sha384 :: Algorithm
sha384 = Algorithm evpSha384

sha512 :: Algorithm
sha512 = Algorithm evpSha512
