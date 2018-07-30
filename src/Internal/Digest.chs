-- Copyright 2018 Google LLC
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

{-# OPTIONS_GHC -Wno-missing-methods #-}

module Internal.Digest
  ( evpMD5, evpSHA1, evpSHA224, evpSHA256, evpSHA384, evpSHA512
  , mallocEVPMDCtx
  , evpDigestInitEx, evpDigestUpdate, evpDigestFinalEx
  , evpMaxMDSize
  ) where

import Foreign (FinalizerPtr, ForeignPtr, Ptr, Storable(alignment, sizeOf))
import Foreign.C.Types
import Foreign.Ptr.Cast (asVoidPtr)

import Foreign.Ptr.CreateWithFinalizer (createWithFinalizer)
{#import Internal.Base#}
import Result

#include <openssl/digest.h>

evpMD5, evpSHA1, evpSHA224, evpSHA256, evpSHA384, evpSHA512 :: Ptr EVPMD
evpMD5    = {#call pure EVP_md5 as ^#}
evpSHA1   = {#call pure EVP_sha1 as ^#}
evpSHA224 = {#call pure EVP_sha224 as ^#}
evpSHA256 = {#call pure EVP_sha256 as ^#}
evpSHA384 = {#call pure EVP_sha384 as ^#}
evpSHA512 = {#call pure EVP_sha512 as ^#}

-- | Memory-safe allocator for 'EVPMDCtx'.
mallocEVPMDCtx :: IO (ForeignPtr EVPMDCtx)
mallocEVPMDCtx =
  createWithFinalizer {#call EVP_MD_CTX_init as ^#} btlsFinalizeEVPMDCtxPtr

foreign import ccall "&btlsFinalizeEVPMDCtx"
  btlsFinalizeEVPMDCtxPtr :: FinalizerPtr EVPMDCtx

evpDigestInitEx :: Ptr EVPMDCtx -> Ptr EVPMD -> Ptr Engine -> IO ()
evpDigestInitEx ctx md engine =
  requireSuccess $ {#call EVP_DigestInit_ex as ^#} ctx md engine

evpDigestUpdate :: Ptr EVPMDCtx -> Ptr a -> CULong -> IO ()
evpDigestUpdate ctx md bytes =
  alwaysSucceeds $ {#call EVP_DigestUpdate as ^#} ctx (asVoidPtr md) bytes

evpDigestFinalEx :: Ptr EVPMDCtx -> Ptr CUChar -> Ptr CUInt -> IO ()
evpDigestFinalEx ctx mdOut outSize =
  alwaysSucceeds $ {#call EVP_DigestFinal_ex as ^#} ctx mdOut outSize

evpMaxMDSize :: Int
evpMaxMDSize = {#const EVP_MAX_MD_SIZE#}

instance Storable EVPMDCtx where
  sizeOf _ = {#sizeof EVP_MD_CTX#}
  alignment _ = {#alignof EVP_MD_CTX#}
