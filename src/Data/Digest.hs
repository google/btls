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

import qualified Data.ByteString.Lazy as ByteString.Lazy
import Foreign.Marshal.Unsafe (unsafeLocalState)

import BTLS.BoringSSL.Base
import BTLS.BoringSSL.Digest
import BTLS.BoringSSLPatterns (initUpdateFinalize)
import BTLS.Cast (asCUCharBuf)
import BTLS.Types (Algorithm(Algorithm), Digest(Digest))

type LazyByteString = ByteString.Lazy.ByteString

md5, sha1, sha224, sha256, sha384, sha512 :: Algorithm
md5    = Algorithm evpMD5
sha1   = Algorithm evpSHA1
sha224 = Algorithm evpSHA224
sha256 = Algorithm evpSHA256
sha384 = Algorithm evpSHA384
sha512 = Algorithm evpSHA512

-- | Hashes according to the given 'Algorithm'.
hash :: Algorithm -> LazyByteString -> Digest
hash (Algorithm md) =
  Digest
    . unsafeLocalState
    . initUpdateFinalize mallocEVPMDCtx initialize evpDigestUpdate finalize
  where
    initialize ctx = evpDigestInitEx ctx md noEngine

    finalize ctx mdOut pOutSize =
      -- 'mdOut' is a 'Ptr CChar'. However, to make life more interesting,
      -- 'evpDigestFinalEx' requires a 'Ptr CUChar'. To work around this,
      -- we're going to cheat and let Haskell reinterpret-cast 'mdOut' to 'Ptr
      -- CUChar.
      evpDigestFinalEx ctx (asCUCharBuf mdOut) pOutSize
