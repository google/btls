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

import qualified Data.Digest.Md5Tests
import qualified Data.Digest.Sha1Tests
import qualified Data.Digest.Sha2Tests

tests :: TestTree
tests = testGroup "Data.Digest"
  [ Data.Digest.Md5Tests.tests
  , Data.Digest.Sha1Tests.tests
  , Data.Digest.Sha2Tests.tests
  ]
