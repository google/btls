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

module Data.DigestTests (tests) where

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit ((@?), testCase)

import Data.Digest (md5, sha1, sha224, sha256, sha384, sha512)
import qualified Data.Digest.MD5Tests
import qualified Data.Digest.SHA1Tests
import qualified Data.Digest.SHA2Tests

tests :: TestTree
tests = testGroup "Data.Digest"
  [ showTests
  , Data.Digest.MD5Tests.tests
  , Data.Digest.SHA1Tests.tests
  , Data.Digest.SHA2Tests.tests ]

showTests = testGroup "show"
  [ testNonEmpty "MD5" (show md5)
  , testNonEmpty "SHA-1" (show sha1)
  , testNonEmpty "SHA-224" (show sha224)
  , testNonEmpty "SHA-256" (show sha256)
  , testNonEmpty "SHA-384" (show sha384)
  , testNonEmpty "SHA-512" (show sha512) ]
  where
    testNonEmpty description string = testCase description $
      not (null string) @? "expected: nonempty string\n but got: " ++ show string
