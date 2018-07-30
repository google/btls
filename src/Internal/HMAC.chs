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

module Internal.HMAC
  ( mallocHMACCtx
  , hmacInitEx, hmacUpdate, hmacFinal
  ) where

import Foreign (FinalizerPtr, ForeignPtr, Ptr, Storable(alignment, sizeOf))
import Foreign.C.Types

import Foreign.Ptr.Cast (asVoidPtr)
import Foreign.Ptr.CreateWithFinalizer (createWithFinalizer)
{#import Internal.Base#}
import Result

#include <openssl/hmac.h>

-- | Memory-safe allocator for 'HMACCtx'.
mallocHMACCtx :: IO (ForeignPtr HMACCtx)
mallocHMACCtx = createWithFinalizer {#call HMAC_CTX_init as ^#} hmacCtxCleanup

foreign import ccall "&HMAC_CTX_cleanup"
  hmacCtxCleanup :: FinalizerPtr HMACCtx

hmacInitEx :: Ptr HMACCtx -> Ptr a -> CULong -> Ptr EVPMD -> Ptr Engine -> IO ()
hmacInitEx ctx bytes size md engine =
  requireSuccess $
    {#call HMAC_Init_ex as ^#} ctx (asVoidPtr bytes) size md engine

hmacUpdate :: Ptr HMACCtx -> Ptr CUChar -> CULong -> IO ()
hmacUpdate ctx bytes size =
  alwaysSucceeds $ {#call HMAC_Update as ^#} ctx bytes size

hmacFinal :: Ptr HMACCtx -> Ptr CUChar -> Ptr CUInt -> IO ()
hmacFinal ctx out outSize =
  requireSuccess $ {#call HMAC_Final as ^#} ctx out outSize

instance Storable HMACCtx where
  sizeOf _ = {#sizeof HMAC_CTX#}
  alignment _ = {#alignof HMAC_CTX#}
