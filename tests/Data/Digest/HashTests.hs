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

module Data.Digest.HashTests
  ( hashTestCase
  , testAgainstCoreutils
  , testAgainstOpenSSL
  , hexDigest
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString.Char8
import qualified Data.ByteString.Lazy as Lazy (ByteString)
import qualified Data.ByteString.Lazy as ByteString.Lazy
import System.IO (hClose, hSetBinaryMode)
import System.Process
  (CreateProcess(std_in, std_out), StdStream(CreatePipe), createProcess_, proc)
import qualified Test.SmallCheck.Series.ByteString.Lazy as ByteString.Lazy.Series
import Test.Tasty (TestTree)
import Test.Tasty.HUnit ((@?=), testCase)
import Test.Tasty.SmallCheck (Property, monadic, over)

import BTLS.TestUtilities (abbreviate, hex)
import Data.Digest (Algorithm, Digest(Digest), hash)

hashTestCase :: Algorithm -> Lazy.ByteString -> ByteString -> TestTree
hashTestCase algo input output =
  testCase (abbreviate input) $ hash algo input @?= hexDigest output

testAgainstCoreutils :: Algorithm -> FilePath -> Property IO
testAgainstCoreutils algo prog =
  over ByteString.Lazy.Series.enumW8s $ \s -> monadic $ do
    theirs <- externalHash (proc prog ["-b"]) s head
    return $ hash algo s == theirs

testAgainstOpenSSL :: Algorithm -> String -> Property IO
testAgainstOpenSSL algo flag =
  over ByteString.Lazy.Series.enumW8s $ \s -> monadic $ do
    theirs <- externalHash (proc "openssl" ["dgst", '-' : flag]) s (!!1)
    return $ hash algo s == theirs

-- | Runs an external hashing command with the specified standard input. Assumes
-- that the process will exit when its standard input is closed.
externalHash :: CreateProcess -> Lazy.ByteString -> ([ByteString] -> ByteString) -> IO Digest
externalHash p s toDigest = do
  (Just stdin, Just stdout, _, _) <-
    createProcess_ "runExternal" (p {std_in = CreatePipe, std_out = CreatePipe})
  hSetBinaryMode stdin True
  ByteString.Lazy.hPut stdin s
  hClose stdin -- causes process to exit
  hexDigest . toDigest . ByteString.Char8.words <$> ByteString.hGetContents stdout

hexDigest :: ByteString -> Digest
hexDigest = Digest . hex
