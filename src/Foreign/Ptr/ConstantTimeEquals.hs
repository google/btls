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

{-# LANGUAGE ScopedTypeVariables #-}

module Foreign.Ptr.ConstantTimeEquals where

import Foreign (Ptr)
import Foreign.C.Types

foreign import ccall "openssl/mem.h CRYPTO_memcmp"
  cryptoMemcmp :: Ptr a -> Ptr a -> CSize -> IO CInt

-- | Directly compares two buffers for equality. This operation takes an amount
-- of time dependent on the specified size but independent of either buffer's
-- contents.
constantTimeEquals :: Ptr a -> Ptr a -> Int -> IO Bool
constantTimeEquals a b size =
  let size' = fromIntegral size :: CSize
  in (== 0) <$> cryptoMemcmp a b size'
