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
import qualified Data.ByteString.Base16 as ByteString.Base16
import qualified Data.ByteString.Char8 as ByteString.Char8
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit ((@?=), testCase)

import Codec.Crypto.HKDF (Salt(Salt), SecretKey(SecretKey), noSalt)
import qualified Codec.Crypto.HKDF as HKDF
import Data.Digest (sha1, sha256)

tests :: TestTree
tests = testGroup "Codec.Crypto.HKDF" [testRFC5869]

-- | Tests from RFC 5869.
testRFC5869 = testGroup "RFC 5869 examples"
  [ t "test case 1"
      sha256
      (SecretKey $ ByteString.replicate 22 0x0b)
      (Salt $ ByteString.pack [0x00 .. 0x0c])
      (SecretKey $ hex "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
  , t "test case 2"
      sha256
      (SecretKey $ ByteString.pack [0x00 .. 0x4f])
      (Salt $ ByteString.pack [0x60 .. 0xaf])
      (SecretKey $ hex "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244")
  , t "test case 3"
      sha256
      (SecretKey $ ByteString.replicate 22 0x0b)
      (Salt "")
      (SecretKey $ hex "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")
  , t "test case 4"
      sha1
      (SecretKey $ ByteString.replicate 11 0x0b)
      (Salt $ ByteString.pack [0x00 .. 0x0c])
      (SecretKey $ hex "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243")
  , t "test case 5"
      sha1
      (SecretKey $ ByteString.pack [0x00 .. 0x4f])
      (Salt $ ByteString.pack [0x60 .. 0xaf])
      (SecretKey $ hex "8adae09a2a307059478d309b26c4115a224cfaf6")
  , t "test case 6"
      sha1
      (SecretKey $ ByteString.replicate 22 0x0b)
      (Salt "")
      (SecretKey $ hex "da8c8a73c7fa77288ec6f5e7c297786aa0d32d01")
  , t "test case 7"
      sha1
      (SecretKey $ ByteString.replicate 22 0x0c)
      noSalt
      (SecretKey $ hex "2adccada18779e7c2077ad2eb19d3f3e731385dd")
  ]
  where
    t name hash ikm salt prk =
      testGroup name [testCase "extract" $ HKDF.extract hash salt ikm @?= prk]

hex :: ByteString -> ByteString
hex s =
  case ByteString.Base16.decode s of
    (r, "") -> r
    _ -> error $ "invalid hex string " ++ ByteString.Char8.unpack s
