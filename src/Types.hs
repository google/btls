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

module Types
  ( Salt(Salt)
  , SecretKey(SecretKey)
  ) where

import Data.ByteString (ByteString)

-- | A salt. Equality comparisons on this type are variable-time.
newtype Salt = Salt ByteString
  deriving (Eq, Ord, Show)

-- | A secret key used as input to a cipher or HMAC. Equality comparisons on
-- this type are variable-time.
newtype SecretKey = SecretKey ByteString
  deriving (Eq, Ord, Show)
