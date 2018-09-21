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

{-# LANGUAGE OverloadedStrings #-}

module BTLS.TestUtilities
  ( abbreviate
  , hex
  ) where

import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Base16.Lazy as L.Base16
import Data.ByteString.Char8 (ByteString, unpack)
import qualified Data.ByteString.Lazy.Char8 as Lazy (ByteString)
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Char (isAscii, isPrint)
import Data.Int (Int64)

abbreviate :: Lazy.ByteString -> String
abbreviate input =
  let maxLen = 22 in
  if L.all isShowable (L.take (maxLen - 2) input)
  then show (addEllipsisIfNecessary (maxLen - 2) input)
  else L.unpack (addEllipsisIfNecessary maxLen (L.Base16.encode input))
  where isShowable c = isAscii c && isPrint c

addEllipsisIfNecessary :: Int64 -> Lazy.ByteString -> Lazy.ByteString
addEllipsisIfNecessary maxLen s =
  let ellipsis = "..."
      ellipsisLen = L.length ellipsis 
      (x, y) = L.splitAt (maxLen - ellipsisLen) s in
  x `L.append` if L.length y <= ellipsisLen then y else ellipsis

hex :: ByteString -> ByteString
hex s =
  case Base16.decode s of
    (r, "") -> r
    _ -> error $ "invalid hex string " ++ unpack s
