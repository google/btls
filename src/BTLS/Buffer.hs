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
  , onBufferOfMaxSize, onBufferOfMaxSize'
  ) where

import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Except (ExceptT, runExceptT)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Unsafe as ByteString
import Foreign (Storable(peek), Ptr, alloca, allocaArray, castPtr)
import Foreign.C.Types

unsafeUseAsCBuffer :: ByteString -> ((Ptr a, CULong) -> IO b) -> IO b
unsafeUseAsCBuffer bs f =
  ByteString.unsafeUseAsCStringLen bs $ \(pStr, len) ->
    f (castPtr pStr, fromIntegral len)

packCUStringLen :: Integral n => (Ptr CUChar, n) -> IO ByteString
packCUStringLen (pStr, len) =
  ByteString.packCStringLen (castPtr pStr, fromIntegral len)

-- | Allocates a buffer, runs a function 'f' to partially fill it, and packs the
-- filled data into a 'ByteString'. 'f' must write the size of the filled data,
-- in bytes and not including any trailing null, into its second argument.
--
-- If 'f' is safe to use under 'unsafeLocalState', this whole function is safe
-- to use under 'unsafeLocalState'.
onBufferOfMaxSize ::
     (Integral size, Storable size)
  => Int
  -> (Ptr CUChar -> Ptr size -> IO ())
  -> IO ByteString
onBufferOfMaxSize maxSize f = do
  Right r <- onBufferOfMaxSize' maxSize (compose2 lift f)
  return r

-- | Like 'onBufferOfMaxSize' but may fail.
onBufferOfMaxSize' ::
     (Integral size, Storable size)
  => Int
  -> (Ptr CUChar -> Ptr size -> ExceptT e IO ())
  -> IO (Either e ByteString)
onBufferOfMaxSize' maxSize f =
  allocaArray maxSize $ \pOut ->
    alloca $ \pOutLen -> runExceptT $ do
      f pOut pOutLen
      outLen <- lift $ peek pOutLen
      lift $ packCUStringLen (pOut, outLen)

compose2 :: (r -> r') -> (a -> b -> r) -> a -> b -> r'
compose2 f g = \a b -> f (g a b)
