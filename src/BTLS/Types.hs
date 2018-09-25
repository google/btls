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

module BTLS.Types where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Base16 as ByteString.Base16
import qualified Data.ByteString.Char8 as ByteString.Char8
import Foreign (Ptr, nullPtr)
import Foreign.C (peekCString)
import Foreign.Marshal.Unsafe (unsafeLocalState)

import BTLS.BoringSSL.Base (EVPMD)
import BTLS.BoringSSL.Digest (evpMDType)
import BTLS.BoringSSL.Obj (objNID2SN)

-- | A cryptographic hash function.
newtype Algorithm = Algorithm (Ptr EVPMD)

instance Eq Algorithm where
  Algorithm a == Algorithm b = evpMDType a == evpMDType b

instance Show Algorithm where
  show (Algorithm md) =
    let sn = objNID2SN (evpMDType md) in
    if sn == nullPtr then "<algorithm>" else unsafeLocalState (peekCString sn)

-- | Context or application-specific information. Equality comparisons on this
-- type are variable-time.
newtype AssociatedData = AssociatedData ByteString
  deriving (Eq, Ord, Show)

-- | The result of a hash operation. Equality comparisons on this type are
-- variable-time.
--
-- The 'Show' instance for this type displays the digest as a hexadecimal string.
newtype Digest = Digest ByteString
  deriving (Eq, Ord)

instance Show Digest where
  show (Digest d) = showHex d

-- | A salt. Equality comparisons on this type are variable-time.
newtype Salt = Salt ByteString
  deriving (Eq, Ord, Show)

-- | A special value used to request that no salt be used.
noSalt :: Salt
noSalt = Salt ByteString.empty

-- | A secret key used as input to a cipher or HMAC. Equality comparisons on
-- this type are variable-time.
newtype SecretKey = SecretKey ByteString
  deriving (Eq, Ord, Show)

showHex :: ByteString -> String
showHex = ByteString.Char8.unpack . ByteString.Base16.encode