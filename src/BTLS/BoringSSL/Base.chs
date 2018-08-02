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

{-# OPTIONS_GHC -Wno-unused-imports #-}

module BTLS.BoringSSL.Base where

import Foreign (Ptr, nullPtr)

#include <openssl/base.h>

-- | The BoringSSL @ENGINE@ type.
data Engine
{#pointer *ENGINE as 'Ptr Engine' -> Engine nocode#}

noEngine :: Ptr Engine
noEngine = nullPtr

-- | The BoringSSL @EVP_MD_CTX@ type, representing the state of a pending
-- hashing operation.
data EVPMDCtx
{#pointer *EVP_MD_CTX as 'Ptr EVPMDCtx' -> EVPMDCtx nocode#}

-- | The BoringSSL @EVP_MD@ type, representing a hash algorithm.
data EVPMD
{#pointer *EVP_MD as 'Ptr EVPMD' -> EVPMD nocode#}

-- | The BoringSSL @HMAC_CTX@ type, representing the state of a pending HMAC
-- operation.
data HMACCtx
{#pointer *HMAC_CTX as 'Ptr HMACCtx' -> HMACCtx nocode#}
