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

module Codec.Crypto.HKDFTests (tests) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase)

import BTLS.Assertions (isRightAndHolds)
import BTLS.TestUtilities (hex)
import Codec.Crypto.HKDF
  (AssociatedData(AssociatedData), Salt(Salt), SecretKey(SecretKey), noSalt)
import qualified Codec.Crypto.HKDF as HKDF
import Data.Digest (sha1, sha256)

tests :: TestTree
tests = testGroup "Codec.Crypto.HKDF" [testRFC5869]

hkdfTestCase name hash ikm salt info prk okm@(SecretKey k) = testGroup name $
  let len = ByteString.length k in
  [ testCase "hkdf" $ HKDF.hkdf hash salt info len ikm `isRightAndHolds` okm
  , testCase "extract" $ HKDF.extract hash salt ikm `isRightAndHolds` prk
  , testCase "expand" $ HKDF.expand hash info len prk `isRightAndHolds` okm ]

-- | Tests from RFC 5869.
testRFC5869 = testGroup "RFC 5869 examples"
  [ hkdfTestCase "test case 1"
      sha256
      (SecretKey $ ByteString.replicate 22 0x0b)
      (Salt $ ByteString.pack [0x00 .. 0x0c])
      (AssociatedData $ ByteString.pack [0xf0 .. 0xf9])
      (hexKey "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
      (hexKey "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
  , hkdfTestCase "test case 2"
      sha256
      (SecretKey $ ByteString.pack [0x00 .. 0x4f])
      (Salt $ ByteString.pack [0x60 .. 0xaf])
      (AssociatedData $ ByteString.pack [0xb0 .. 0xff])
      (hexKey "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244")
      (hexKey "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87")
  , hkdfTestCase "test case 3"
      sha256
      (SecretKey $ ByteString.replicate 22 0x0b)
      (Salt "")
      (AssociatedData "")
      (hexKey "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")
      (hexKey "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
  , hkdfTestCase "test case 4"
      sha1
      (SecretKey $ ByteString.replicate 11 0x0b)
      (Salt $ ByteString.pack [0x00 .. 0x0c])
      (AssociatedData $ ByteString.pack [0xf0 .. 0xf9])
      (hexKey "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243")
      (hexKey "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896")
  , hkdfTestCase "test case 5"
      sha1
      (SecretKey $ ByteString.pack [0x00 .. 0x4f])
      (Salt $ ByteString.pack [0x60 .. 0xaf])
      (AssociatedData $ ByteString.pack [0xb0 .. 0xff])
      (hexKey "8adae09a2a307059478d309b26c4115a224cfaf6")
      (hexKey "0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4")
  , hkdfTestCase "test case 6"
      sha1
      (SecretKey $ ByteString.replicate 22 0x0b)
      (Salt "")
      (AssociatedData "")
      (hexKey "da8c8a73c7fa77288ec6f5e7c297786aa0d32d01")
      (hexKey "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918")
  , hkdfTestCase "test case 7"
      sha1
      (SecretKey $ ByteString.replicate 22 0x0c)
      noSalt
      (AssociatedData "")
      (hexKey "2adccada18779e7c2077ad2eb19d3f3e731385dd")
      (hexKey "2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48") ]

hexKey :: ByteString -> SecretKey
hexKey = SecretKey . hex
