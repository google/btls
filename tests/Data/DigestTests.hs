module Data.DigestTests
  ( tests
  ) where

import Test.Tasty (TestTree, testGroup)

import qualified Data.Digest.Md5Tests
import qualified Data.Digest.Sha1Tests
import qualified Data.Digest.Sha2Tests

tests :: TestTree
tests =
  testGroup
    "Data.Digest"
    [ Data.Digest.Md5Tests.tests
    , Data.Digest.Sha1Tests.tests
    , Data.Digest.Sha2Tests.tests
    ]
