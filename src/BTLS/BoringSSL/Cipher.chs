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

module BTLS.BoringSSL.Cipher
  ( evpRC4
  , mallocEVPCipherCtx
  , evpCipherInitEx, evpCipherUpdate, evpCipherFinalEx
  , evpCipherCtxSetKeyLength
  , evpCipherNID, evpCipherBlockSize, evpCipherKeyLength, evpCipherIVLength
  , CipherDirection(ReuseDirection, Decrypt, Encrypt)
  ) where

import Data.ByteString (ByteString)
import Foreign (FinalizerPtr, ForeignPtr, Ptr, Storable(alignment, sizeOf), withForeignPtr)
import Foreign.C.Types

{#import BTLS.BoringSSL.Base#}
import BTLS.Buffer (unsafeUseAsCBuffer)
import BTLS.CreateWithFinalizer (createWithFinalizer)

#include <openssl/cipher.h>

data CipherDirection = ReuseDirection | Decrypt | Encrypt
  deriving (Eq, Show)

instance Enum CipherDirection where
  fromEnum ReuseDirection = -1
  fromEnum Decrypt = 0
  fromEnum Encrypt = 1

{#fun pure EVP_rc4 as evpRC4 {} -> `Ptr EVPCipher'#}

-- | Memory-safe allocator for 'EVPCipherCtx'.
mallocEVPCipherCtx :: IO (ForeignPtr EVPCipherCtx)
mallocEVPCipherCtx =
  createWithFinalizer {#call EVP_CIPHER_CTX_init as ^#} btlsFinalizeEVPCipherCtxPtr

foreign import ccall "&btlsFinalizeEVPCipherCtx"
  btlsFinalizeEVPCipherCtxPtr :: FinalizerPtr EVPCipherCtx

{#fun EVP_CipherInit_ex as evpCipherInitEx
  { withForeignPtr* `ForeignPtr EVPCipherCtx'
  , `Ptr EVPCipher'
  , `Ptr Engine'
  , id `Ptr CUChar'
  , id `Ptr CUChar'
  , 'fromIntegral . fromEnum' `CipherDirection'
  } -> `Int'#}

{#fun EVP_CipherUpdate as evpCipherUpdate
  { withForeignPtr* `ForeignPtr EVPCipherCtx'
  , id `Ptr CUChar'
  , id `Ptr CInt'
  , unsafeUseAsCBuffer* `ByteString'&
  } -> `Int'#}

{#fun EVP_CipherFinal_ex as evpCipherFinalEx
  { withForeignPtr* `ForeignPtr EVPCipherCtx'
  , id `Ptr CUChar'
  , id `Ptr CInt'
  } -> `Int'#}

{#fun EVP_CIPHER_CTX_set_key_length as evpCipherCtxSetKeyLength
  {withForeignPtr* `ForeignPtr EVPCipherCtx', `Int'} -> `Int'#}

{#fun pure EVP_CIPHER_nid as evpCipherNID {`Ptr EVPCipher'} -> `Int'#}

{#fun pure EVP_CIPHER_block_size as evpCipherBlockSize
  {`Ptr EVPCipher'} -> `Int'#}

{#fun pure EVP_CIPHER_key_length as evpCipherKeyLength
  {`Ptr EVPCipher'} -> `Int'#}

{#fun pure EVP_CIPHER_iv_length as evpCipherIVLength
  {`Ptr EVPCipher'} -> `Int'#}

instance Storable EVPCipherCtx where
  sizeOf _ = {#sizeof EVP_CIPHER_CTX#}
  alignment _ = {#alignof EVP_CIPHER_CTX#}
