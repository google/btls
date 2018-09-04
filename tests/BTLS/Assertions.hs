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

module BTLS.Assertions
  ( isRightAndHolds
  ) where

import Control.Monad (unless)
import Test.Tasty.HUnit (Assertion, assertFailure)

isRightAndHolds :: (Eq a, Show a, Show e) => Either e a -> a -> Assertion
actual@(Left _) `isRightAndHolds` _ =
  assertFailure ("expected: Right _\n but got: " ++ show actual)
Right actual `isRightAndHolds` expected =
  unless (expected == actual) $
    assertFailure ("expected: Right " ++ show expected ++ "\n but got: Right " ++ show actual)
