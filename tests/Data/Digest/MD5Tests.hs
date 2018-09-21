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

module Data.Digest.MD5Tests (tests) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as Lazy (ByteString)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.SmallCheck (testProperty)

import Data.Digest (md5)
import Data.Digest.HashTests
  (hashTestCase, testAgainstCoreutils, testAgainstOpenSSL)

tests :: TestTree
tests = testGroup "MD5"
  [ testRFCExamples
  , testGoExamples
  , testCoreutilsConformance
  , testOpenSSLConformance ]

md5TestCase :: Lazy.ByteString -> ByteString -> TestTree
md5TestCase = hashTestCase md5

-- | MD5 example vectors from RFC 1321.
testRFCExamples = testGroup "RFC 1321 examples"
  [ md5TestCase "" "d41d8cd98f00b204e9800998ecf8427e"
  , md5TestCase "a" "0cc175b9c0f1b6a831c399e269772661"
  , md5TestCase "abc" "900150983cd24fb0d6963f7d28e17f72"
  , md5TestCase "message digest" "f96b697d7cb7938d525a2f31aaf161d0"
  , md5TestCase "abcdefghijklmnopqrstuvwxyz" "c3fcd3d76192e4007dfb496cca67e13b"
  , md5TestCase "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" "d174ab98d277d9f5a5611c2c9f419d9f"
  , md5TestCase "12345678901234567890123456789012345678901234567890123456789012345678901234567890" "57edf4a22be3c955ac49da2e2107b67a" ]

-- | Test vectors used to test the Go MD5 implementation.
testGoExamples = testGroup "Go tests" $
  [ md5TestCase "" "d41d8cd98f00b204e9800998ecf8427e"
  , md5TestCase "a" "0cc175b9c0f1b6a831c399e269772661"
  , md5TestCase "ab" "187ef4436122d1cc2f40dc2b92f0eba0"
  , md5TestCase "abc" "900150983cd24fb0d6963f7d28e17f72"
  , md5TestCase "abcd" "e2fc714c4727ee9395f324cd2e7f331f"
  , md5TestCase "abcde" "ab56b4d92b40713acc5af89985d4b786"
  , md5TestCase "abcdef" "e80b5017098950fc58aad83c8c14978e"
  , md5TestCase "abcdefg" "7ac66c0f148de9519b8bd264312c4d64"
  , md5TestCase "abcdefgh" "e8dc4081b13434b45189a720b77b6818"
  , md5TestCase "abcdefghi" "8aa99b1f439ff71293e95357bac6fd94"
  , md5TestCase "abcdefghij" "a925576942e94b2ef57a066101b48876"
  , md5TestCase "Discard medicine more than two years old." "d747fc1719c7eacb84058196cfe56d57"
  , md5TestCase "He who has a shady past knows that nice guys finish last." "bff2dcb37ef3a44ba43ab144768ca837"
  , md5TestCase "I wouldn't marry him with a ten foot pole." "0441015ecb54a7342d017ed1bcfdbea5"
  , md5TestCase "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave" "9e3cac8e9e9757a60c3ea391130d3689"
  , md5TestCase "The days of the digital watch are numbered.  -Tom Stoppard" "a0f04459b031f916a59a35cc482dc039"
  , md5TestCase "Nepal premier won't resign." "e7a48e0fe884faf31475d2a04b1362cc"
  , md5TestCase "For every action there is an equal and opposite government program." "637d2fe925c07c113800509964fb0e06"
  , md5TestCase "His money is twice tainted: 'taint yours and 'taint mine." "834a8d18d5c6562119cf4c7f5086cb71"
  , md5TestCase "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977" "de3a4d2fd6c73ec2db2abad23b444281"
  , md5TestCase "It's a tiny change to the code and not completely disgusting. - Bob Manchek" "acf203f997e2cf74ea3aff86985aefaf"
  , md5TestCase "size:  a.out:  bad magic" "e1c1384cb4d2221dfdd7c795a4222c9a"
  , md5TestCase "The major problem is with sendmail.  -Mark Horton" "c90f3ddecc54f34228c063d7525bf644"
  , md5TestCase "Give me a rock, paper and scissors and I will move the world.  CCFestoon" "cdf7ab6c1fd49bd9933c43f3ea5af185"
  , md5TestCase "If the enemy is within range, then so are you." "83bc85234942fc883c063cbd7f0ad5d0"
  , md5TestCase "It's well we cannot hear the screams/That we create in others' dreams." "277cbe255686b48dd7e8f389394d9299"
  , md5TestCase "You remind me of a TV show, but that's all right: I watch it anyway." "fd3fb0a7ffb8af16603f3d3af98f8e1f"
  , md5TestCase "C is as portable as Stonehedge!!" "469b13a78ebf297ecda64d4723655154"
  , md5TestCase "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley" "63eb3a2f466410104731c4b037600110"
  , md5TestCase "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule" "72c2ed7592debca1c90fc0100f931a2f"
  , md5TestCase "How can you write a big system without C++?  -Paul Glick" "132f7619d33b523b1d9e5bd8e0928355" ]

-- | Tests our MD5 implementation against coreutils'.
testCoreutilsConformance = testProperty "conformance with coreutils" $
  testAgainstCoreutils md5 "md5sum"

-- | Tests our MD5 implementation against openssl(1)'s.
testOpenSSLConformance = testProperty "conformance with OpenSSL" $
  testAgainstOpenSSL md5 "md5"
