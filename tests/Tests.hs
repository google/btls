module Main
  ( main
  ) where

import Test.Tasty (defaultMain, testGroup)

import qualified Data.Digest.Sha2Tests

main :: IO ()
main = defaultMain $ testGroup "btls" [Data.Digest.Sha2Tests.tests]
