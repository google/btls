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

import Data.Bits (Bits((.&.)), shiftR)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Char (intToDigit)
import Data.Word (Word8)
import Foreign (Ptr)

import BTLS.BoringSSL.Base (EVPMD)

-- | A cryptographic hash function.
newtype Algorithm = Algorithm (Ptr EVPMD)

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
  show (Digest d) = ByteString.foldr showHexPadded [] d
    where
      showHexPadded b xs =
        hexit (b `shiftR` 4 .&. 0x0f) : hexit (b .&. 0x0f) : xs
      hexit = intToDigit . fromIntegral :: Word8 -> Char

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
