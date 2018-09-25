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

module BTLS.BoringSSL.Digest
  ( evpMD5, evpSHA1, evpSHA224, evpSHA256, evpSHA384, evpSHA512
  , mallocEVPMDCtx
  , evpDigestInitEx, evpDigestUpdate, evpDigestFinalEx
  , evpMaxMDSize
  , evpMDType
  ) where

import Data.ByteString (ByteString)
import Foreign
  (FinalizerPtr, ForeignPtr, Ptr, Storable(alignment, sizeOf), withForeignPtr)
import Foreign.C.Types

{#import BTLS.BoringSSL.Base#}
import BTLS.Buffer (unsafeUseAsCBuffer)
import BTLS.CreateWithFinalizer (createWithFinalizer)
import BTLS.Result

#include <openssl/digest.h>

{#fun pure EVP_md5    as evpMD5 {} -> `Ptr EVPMD'#}
{#fun pure EVP_sha1   as evpSHA1 {} -> `Ptr EVPMD'#}
{#fun pure EVP_sha224 as evpSHA224 {} -> `Ptr EVPMD'#}
{#fun pure EVP_sha256 as evpSHA256 {} -> `Ptr EVPMD'#}
{#fun pure EVP_sha384 as evpSHA384 {} -> `Ptr EVPMD'#}
{#fun pure EVP_sha512 as evpSHA512 {} -> `Ptr EVPMD'#}

-- | Memory-safe allocator for 'EVPMDCtx'.
mallocEVPMDCtx :: IO (ForeignPtr EVPMDCtx)
mallocEVPMDCtx =
  createWithFinalizer {#call EVP_MD_CTX_init as ^#} btlsFinalizeEVPMDCtxPtr

foreign import ccall "&btlsFinalizeEVPMDCtx"
  btlsFinalizeEVPMDCtxPtr :: FinalizerPtr EVPMDCtx

{#fun EVP_DigestInit_ex as evpDigestInitEx
  {withForeignPtr* `ForeignPtr EVPMDCtx', `Ptr EVPMD', `Ptr Engine'}
  -> `()' requireSuccess*-#}

{#fun EVP_DigestUpdate as evpDigestUpdate
  {withForeignPtr* `ForeignPtr EVPMDCtx', unsafeUseAsCBuffer* `ByteString'&}
  -> `()' alwaysSucceeds*-#}

{#fun EVP_DigestFinal_ex as evpDigestFinalEx
  {withForeignPtr* `ForeignPtr EVPMDCtx', id `Ptr CUChar', id `Ptr CUInt'}
  -> `()' alwaysSucceeds*-#}

evpMaxMDSize :: Int
evpMaxMDSize = {#const EVP_MAX_MD_SIZE#}

{#fun pure EVP_MD_type as evpMDType {`Ptr EVPMD'} -> `Int'#}

instance Storable EVPMDCtx where
  sizeOf _ = {#sizeof EVP_MD_CTX#}
  alignment _ = {#alignof EVP_MD_CTX#}
