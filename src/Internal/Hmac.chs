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
{-# OPTIONS_GHC -Wno-orphans #-}

module Internal.Hmac
  ( mallocHmacCtx
  , hmacInitEx, hmacUpdate, hmacFinal
  ) where

import Foreign
  (FinalizerPtr, ForeignPtr, Ptr, Storable(alignment, sizeOf),
   addForeignPtrFinalizer, mallocForeignPtr, withForeignPtr)
import Foreign.C.Types

import Foreign.Ptr.Cast (asVoidPtr)
{#import Internal.Base#}
import Result

#include <openssl/hmac.h>

-- | Memory-safe allocator for 'HmacCtx'.
mallocHmacCtx :: IO (ForeignPtr HmacCtx)
mallocHmacCtx = do
  fp <- mallocForeignPtr
  withForeignPtr fp {#call HMAC_CTX_init as ^#}
  addForeignPtrFinalizer hmacCtxCleanup fp
  return fp

foreign import ccall "&HMAC_CTX_cleanup"
  hmacCtxCleanup :: FinalizerPtr HmacCtx

hmacInitEx :: Ptr HmacCtx -> Ptr a -> CULong -> Ptr EvpMd -> Ptr Engine -> IO ()
hmacInitEx ctx bytes size md engine =
  requireSuccess $
    {#call HMAC_Init_ex as ^#} ctx (asVoidPtr bytes) size md engine

hmacUpdate :: Ptr HmacCtx -> Ptr CUChar -> CULong -> IO ()
hmacUpdate ctx bytes size =
  alwaysSucceeds $ {#call HMAC_Update as ^#} ctx bytes size

hmacFinal :: Ptr HmacCtx -> Ptr CUChar -> Ptr CUInt -> IO ()
hmacFinal ctx out outSize =
  requireSuccess $ {#call HMAC_Final as ^#} ctx out outSize

instance Storable HmacCtx where
  sizeOf _ = {#sizeof HMAC_CTX#}
  alignment _ = {#alignof HMAC_CTX#}
