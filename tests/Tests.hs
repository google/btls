module Main
  ( main
  ) where

import Test.Tasty (defaultMain, testGroup)

import qualified Data.DigestTests
import qualified Data.HmacTests

main :: IO ()
main =
  defaultMain $ testGroup "btls" [Data.DigestTests.tests, Data.HmacTests.tests]
