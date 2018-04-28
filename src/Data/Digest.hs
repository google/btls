-- Copyright 2017 Google LLC
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

module Data.Digest
  ( Algorithm
  , Digest
  , hash
  , md5
  , sha1
  , sha224, sha256, sha384, sha512
  ) where

import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Unsafe as ByteString
import qualified Data.ByteString.Lazy as ByteString.Lazy
import Foreign (Storable(peek), alloca, allocaArray, withForeignPtr)
import Foreign.Marshal.Unsafe (unsafeLocalState)
import Unsafe.Coerce (unsafeCoerce)

import Data.Digest.Internal
import Internal.Base
import Internal.Digest

type LazyByteString = ByteString.Lazy.ByteString

md5, sha1, sha224, sha256, sha384, sha512 :: Algorithm
md5    = Algorithm evpMd5
sha1   = Algorithm evpSha1
sha224 = Algorithm evpSha224
sha256 = Algorithm evpSha256
sha384 = Algorithm evpSha384
sha512 = Algorithm evpSha512

-- | Hashes according to the given 'Algorithm'.
hash :: Algorithm -> LazyByteString -> Digest
hash (Algorithm md) bytes =
  unsafeLocalState $ do
    ctxFP <- mallocEvpMdCtx
    withForeignPtr ctxFP $ \ctx -> do
      evpDigestInitEx ctx md noEngine
      mapM_ (updateBytes ctx) (ByteString.Lazy.toChunks bytes)
      d <-
        allocaArray evpMaxMdSize $ \mdOut ->
          alloca $ \pOutSize -> do
            evpDigestFinalEx ctx mdOut pOutSize
            outSize <- fromIntegral <$> peek pOutSize
            -- 'mdOut' is a 'Ptr CUChar'. However, to make life more
            -- interesting, 'CString' is a 'Ptr CChar', and 'CChar' is signed.
            -- This is especially unfortunate given that all we really want to
            -- do is convert to a 'ByteString', which is unsigned. To work
            -- around it, we're going to cheat and let Haskell reinterpret-cast
            -- 'mdOut' to 'Ptr CChar' before it does its 'ByteString' ingestion.
            ByteString.packCStringLen (unsafeCoerce mdOut, outSize)
      return (Digest d)
  where
    updateBytes ctx chunk =
      -- 'mdUpdate' treats its @buf@ argument as @const@, so the sharing
      -- inherent in 'ByteString.unsafeUseAsCStringLen' is fine.
      ByteString.unsafeUseAsCStringLen chunk $ \(buf, len) ->
        evpDigestUpdate ctx buf (fromIntegral len)
