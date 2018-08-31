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

module BTLS.Buffer
  ( unsafeUseAsCBuffer
  , packCUStringLen
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Unsafe as ByteString
import Foreign (Ptr, castPtr)
import Foreign.C.Types
import Unsafe.Coerce (unsafeCoerce)

unsafeUseAsCBuffer :: ByteString -> ((Ptr a, CULong) -> IO b) -> IO b
unsafeUseAsCBuffer bs f =
  ByteString.unsafeUseAsCStringLen bs $ \(pStr, len) ->
    f (castPtr pStr, fromIntegral len)

packCUStringLen :: Integral n => (Ptr CUChar, n) -> IO ByteString
packCUStringLen (pStr, len) =
  ByteString.packCStringLen (asCCharBuf pStr, fromIntegral len)

asCCharBuf :: Ptr CUChar -> Ptr CChar
asCCharBuf = unsafeCoerce
