{-# LANGUAGE OverloadedStrings #-}

module Data.Digest.HashTests
  ( goTestCase
  , testAgainstCoreutils
  , testAgainstOpenssl
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import System.IO (hClose, hGetContents, hSetBinaryMode)
import System.Process
       (CreateProcess(std_in, std_out), StdStream(CreatePipe),
        createProcess_, proc)
import qualified Test.SmallCheck.Series.ByteString
       as ByteString.Series
import Test.Tasty (TestTree)
import Test.Tasty.HUnit ((@?=), testCase)
import Test.Tasty.SmallCheck (Property, monadic, over)

goTestCase :: (ByteString -> String) -> (String, ByteString) -> TestTree
goTestCase f (output, input) = testCase description (f input @?= output)
  where
    description =
      let (x, y) = ByteString.splitAt 11 input
      in show (x `ByteString.append` if ByteString.null y then "" else "...")

testAgainstCoreutils :: (ByteString -> String) -> FilePath -> Property IO
testAgainstCoreutils f prog =
  over ByteString.Series.enumW8s $ \s ->
    monadic $ do
      theirs <- runExternal (proc prog ["-b"]) s
      return (f s == head (words theirs))

-- | Runs an external hashing command with the specified standard input. Assumes
-- that the process will exit when its standard input is closed.
runExternal :: CreateProcess -> ByteString -> IO String
runExternal p s = do
  (Just stdin, Just stdout, _, _) <-
    createProcess_ "runExternal" (p {std_in = CreatePipe, std_out = CreatePipe})
  hSetBinaryMode stdin True
  ByteString.hPut stdin s
  hClose stdin -- causes process to exit
  hGetContents stdout

testAgainstOpenssl :: (ByteString -> String) -> String -> Property IO
testAgainstOpenssl f flag =
  over ByteString.Series.enumW8s $ \s ->
    monadic $ do
      theirs <- runExternal (proc "openssl" ["dgst", '-' : flag]) s
      return (f s == words theirs !! 1)
