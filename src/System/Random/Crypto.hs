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

{-|
  Module: System.Random.Crypto
  Description: Cryptographically secure pseudorandom number generator
  Copyright: 2018 Google LLC
  License: Apache License, version 2.0
-}
module System.Random.Crypto
  ( randomBytes
  ) where

import Data.ByteString (ByteString)
import Foreign (allocaArray)

import BTLS.BoringSSL.Rand (randBytes)
import BTLS.Buffer (packCUStringLen)

-- | Generates a cryptographically random buffer of the specified size (in
-- bytes).
randomBytes :: Int -> IO ByteString
randomBytes len =
  allocaArray len $ \pBuf -> do
    randBytes pBuf len
    packCUStringLen (pBuf, len)
