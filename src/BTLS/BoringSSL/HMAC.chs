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

module BTLS.BoringSSL.HMAC
  ( mallocHMACCtx
  , hmacInitEx, hmacUpdate, hmacFinal
  ) where

import Data.ByteString (ByteString)
import Foreign (FinalizerPtr, ForeignPtr, Ptr, Storable(alignment, sizeOf))
import Foreign.C.Types

{#import BTLS.BoringSSL.Base#}
import BTLS.Buffer (unsafeUseAsCBuffer)
import BTLS.CreateWithFinalizer (createWithFinalizer)
import BTLS.Result

#include <openssl/hmac.h>

-- | Memory-safe allocator for 'HMACCtx'.
mallocHMACCtx :: IO (ForeignPtr HMACCtx)
mallocHMACCtx = createWithFinalizer {#call HMAC_CTX_init as ^#} hmacCtxCleanup

foreign import ccall "&HMAC_CTX_cleanup"
  hmacCtxCleanup :: FinalizerPtr HMACCtx

{#fun HMAC_Init_ex as hmacInitEx
  {`Ptr HMACCtx', unsafeUseAsCBuffer* `ByteString'&, `Ptr EVPMD', `Ptr Engine'}
  -> `()' requireSuccess*-#}

{#fun HMAC_Update as hmacUpdate
  {`Ptr HMACCtx', unsafeUseAsCBuffer* `ByteString'&} -> `()' alwaysSucceeds*-#}

{#fun HMAC_Final as hmacFinal
  {`Ptr HMACCtx', id `Ptr CUChar', id `Ptr CUInt'} -> `()' requireSuccess*-#}

instance Storable HMACCtx where
  sizeOf _ = {#sizeof HMAC_CTX#}
  alignment _ = {#alignof HMAC_CTX#}
