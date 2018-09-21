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

module Data.Digest.SHA1Tests (tests) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as Lazy (ByteString)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit ((@?=), testCase)
import Test.Tasty.SmallCheck (testProperty)

import Data.Digest (hash, sha1)
import Data.Digest.HashTests
  (hashTestCase, hexDigest, testAgainstCoreutils, testAgainstOpenSSL)

tests :: TestTree
tests = testGroup "SHA-1"
  [ testNISTExamples
  , testGoExamples
  , testCoreutilsConformance
  , testOpenSSLConformance ]

sha1TestCase :: Lazy.ByteString -> ByteString -> TestTree
sha1TestCase = hashTestCase sha1

-- | SHA-1 example vectors from
-- https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values.
testNISTExamples = testGroup "NIST examples"
  [ testCase "one-block" $ hash sha1 "abc" @?= hexDigest "a9993e364706816aba3e25717850c26c9cd0d89d"
  , testCase "two-block" $ hash sha1 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" @?= hexDigest "84983e441c3bd26ebaae4aa1f95129e5e54670f1" ]

-- | Test vectors used to test the Go SHA-1 implementation.
testGoExamples = testGroup "Go tests"
  [ sha1TestCase "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n" "76245dbf96f661bd221046197ab8b9f063f11bad"
  , sha1TestCase "" "da39a3ee5e6b4b0d3255bfef95601890afd80709"
  , sha1TestCase "a" "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8"
  , sha1TestCase "ab" "da23614e02469a0d7c7bd1bdab5c9c474b1904dc"
  , sha1TestCase "abc" "a9993e364706816aba3e25717850c26c9cd0d89d"
  , sha1TestCase "abcd" "81fe8bfe87576c3ecb22426f8e57847382917acf"
  , sha1TestCase "abcde" "03de6c570bfe24bfc328ccd7ca46b76eadaf4334"
  , sha1TestCase "abcdef" "1f8ac10f23c5b5bc1167bda84b833e5c057a77d2"
  , sha1TestCase "abcdefg" "2fb5e13419fc89246865e7a324f476ec624e8740"
  , sha1TestCase "abcdefgh" "425af12a0743502b322e93a015bcf868e324d56a"
  , sha1TestCase "abcdefghi" "c63b19f1e4c8b5f76b25c49b8b87f57d8e4872a1"
  , sha1TestCase "abcdefghij" "d68c19a0a345b7eab78d5e11e991c026ec60db63"
  , sha1TestCase "Discard medicine more than two years old." "ebf81ddcbe5bf13aaabdc4d65354fdf2044f38a7"
  , sha1TestCase "He who has a shady past knows that nice guys finish last." "e5dea09392dd886ca63531aaa00571dc07554bb6"
  , sha1TestCase "I wouldn't marry him with a ten foot pole." "45988f7234467b94e3e9494434c96ee3609d8f8f"
  , sha1TestCase "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave" "55dee037eb7460d5a692d1ce11330b260e40c988"
  , sha1TestCase "The days of the digital watch are numbered.  -Tom Stoppard" "b7bc5fb91080c7de6b582ea281f8a396d7c0aee8"
  , sha1TestCase "Nepal premier won't resign." "c3aed9358f7c77f523afe86135f06b95b3999797"
  , sha1TestCase "For every action there is an equal and opposite government program." "6e29d302bf6e3a5e4305ff318d983197d6906bb9"
  , sha1TestCase "His money is twice tainted: 'taint yours and 'taint mine." "597f6a540010f94c15d71806a99a2c8710e747bd"
  , sha1TestCase "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977" "6859733b2590a8a091cecf50086febc5ceef1e80"
  , sha1TestCase "It's a tiny change to the code and not completely disgusting. - Bob Manchek" "514b2630ec089b8aee18795fc0cf1f4860cdacad"
  , sha1TestCase "size:  a.out:  bad magic" "c5ca0d4a7b6676fc7aa72caa41cc3d5df567ed69"
  , sha1TestCase "The major problem is with sendmail.  -Mark Horton" "74c51fa9a04eadc8c1bbeaa7fc442f834b90a00a"
  , sha1TestCase "Give me a rock, paper and scissors and I will move the world.  CCFestoon" "0b4c4ce5f52c3ad2821852a8dc00217fa18b8b66"
  , sha1TestCase "If the enemy is within range, then so are you." "3ae7937dd790315beb0f48330e8642237c61550a"
  , sha1TestCase "It's well we cannot hear the screams/That we create in others' dreams." "410a2b296df92b9a47412b13281df8f830a9f44b"
  , sha1TestCase "You remind me of a TV show, but that's all right: I watch it anyway." "841e7c85ca1adcddbdd0187f1289acb5c642f7f5"
  , sha1TestCase "C is as portable as Stonehedge!!" "163173b825d03b952601376b25212df66763e1db"
  , sha1TestCase "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley" "32b0377f2687eb88e22106f133c586ab314d5279"
  , sha1TestCase "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule" "0885aaf99b569542fd165fa44e322718f4a984e0"
  , sha1TestCase "How can you write a big system without C++?  -Paul Glick" "6627d6904d71420b0bf3886ab629623538689f45" ]

-- | Tests our SHA-1 implementation against coreutils'.
testCoreutilsConformance = testProperty "conformance with coreutils" $
  testAgainstCoreutils sha1 "sha1sum"

-- | Tests our SHA-1 implementation against openssl(1)'s.
testOpenSSLConformance = testProperty "conformance with OpenSSL" $
  testAgainstOpenSSL sha1 "sha1"
