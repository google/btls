module Main
  ( main
  ) where

import Test.Tasty (defaultMain, testGroup)

import qualified Data.DigestTests

main :: IO ()
main = defaultMain $ testGroup "btls" [Data.DigestTests.tests]
