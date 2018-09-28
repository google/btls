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

module Codec.Crypto.EncryptionTests (tests) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as ByteString.Lazy
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit ((@?), Assertion, assertFailure, testCase)

import BTLS.TestUtilities (hex, showHex)
import Codec.Crypto.Encryption
  (CipherDirection(Encrypt), CipherParams(..), Error, doCipher, rc4)

tests :: TestTree
tests = testGroup "Codec.Crypto.Encryption" [testRFC6229]

-- | Tests from RFC 6229.
testRFC6229 = testGroup "RFC 6229 examples (RC4)"
  [ index40, index56, index64, index80, index128, index192, index256
  , ietf40, ietf56, ietf64, ietf80, ietf128, ietf192, ietf256 ]
  where
    rc4WithKey key = doCipher
                       CipherParams { cipher = rc4
                                    , secretKey = hex key
                                    , iv = ""
                                    , direction = Encrypt }
                       (ByteString.Lazy.replicate 0x1010 0)
    index40 = testGroup "index40" $
      let ciphertext = rc4WithKey "0102030405" in
      [ indexCheckTestCase 0x0000 (hex "b2396305f03dc027ccc3524a0a1118a8") ciphertext
      , indexCheckTestCase 0x0010 (hex "6982944f18fc82d589c403a47a0d0919") ciphertext
      , indexCheckTestCase 0x00f0 (hex "28cb1132c96ce286421dcaadb8b69eae") ciphertext
      , indexCheckTestCase 0x0100 (hex "1cfcf62b03eddb641d77dfcf7f8d8c93") ciphertext
      , indexCheckTestCase 0x01f0 (hex "42b7d0cdd918a8a33dd51781c81f4041") ciphertext
      , indexCheckTestCase 0x0200 (hex "6459844432a7da923cfb3eb4980661f6") ciphertext
      , indexCheckTestCase 0x02f0 (hex "ec10327bde2beefd18f9277680457e22") ciphertext
      , indexCheckTestCase 0x0300 (hex "eb62638d4f0ba1fe9fca20e05bf8ff2b") ciphertext
      , indexCheckTestCase 0x03f0 (hex "45129048e6a0ed0b56b490338f078da5") ciphertext
      , indexCheckTestCase 0x0400 (hex "30abbcc7c20b01609f23ee2d5f6bb7df") ciphertext
      , indexCheckTestCase 0x05f0 (hex "3294f744d8f9790507e70f62e5bbceea") ciphertext
      , indexCheckTestCase 0x0600 (hex "d8729db41882259bee4f825325f5a130") ciphertext
      , indexCheckTestCase 0x07f0 (hex "1eb14a0c13b3bf47fa2a0ba93ad45b8b") ciphertext
      , indexCheckTestCase 0x0800 (hex "cc582f8ba9f265e2b1be9112e975d2d7") ciphertext
      , indexCheckTestCase 0x0bf0 (hex "f2e30f9bd102ecbf75aaade9bc35c43c") ciphertext
      , indexCheckTestCase 0x0c00 (hex "ec0e11c479dc329dc8da7968fe965681") ciphertext
      , indexCheckTestCase 0x0ff0 (hex "068326a2118416d21f9d04b2cd1ca050") ciphertext
      , indexCheckTestCase 0x1000 (hex "ff25b58995996707e51fbdf08b34d875") ciphertext ]
    index56 = testGroup "index56" $
      let ciphertext = rc4WithKey "01020304050607" in
      [ indexCheckTestCase 0x0000 (hex "293f02d47f37c9b633f2af5285feb46b") ciphertext
      , indexCheckTestCase 0x0010 (hex "e620f1390d19bd84e2e0fd752031afc1") ciphertext
      , indexCheckTestCase 0x00f0 (hex "914f02531c9218810df60f67e338154c") ciphertext
      , indexCheckTestCase 0x0100 (hex "d0fdb583073ce85ab83917740ec011d5") ciphertext
      , indexCheckTestCase 0x01f0 (hex "75f81411e871cffa70b90c74c592e454") ciphertext
      , indexCheckTestCase 0x0200 (hex "0bb87202938dad609e87a5a1b079e5e4") ciphertext
      , indexCheckTestCase 0x02f0 (hex "c2911246b612e7e7b903dfeda1dad866") ciphertext
      , indexCheckTestCase 0x0300 (hex "32828f91502b6291368de8081de36fc2") ciphertext
      , indexCheckTestCase 0x03f0 (hex "f3b9a7e3b297bf9ad804512f9063eff1") ciphertext
      , indexCheckTestCase 0x0400 (hex "8ecb67a9ba1f55a5a067e2b026a3676f") ciphertext
      , indexCheckTestCase 0x05f0 (hex "d2aa902bd42d0d7cfd340cd45810529f") ciphertext
      , indexCheckTestCase 0x0600 (hex "78b272c96e42eab4c60bd914e39d06e3") ciphertext
      , indexCheckTestCase 0x07f0 (hex "f4332fd31a079396ee3cee3f2a4ff049") ciphertext
      , indexCheckTestCase 0x0800 (hex "05459781d41fda7f30c1be7e1246c623") ciphertext
      , indexCheckTestCase 0x0bf0 (hex "adfd3868b8e51485d5e610017e3dd609") ciphertext
      , indexCheckTestCase 0x0c00 (hex "ad26581c0c5be45f4cea01db2f3805d5") ciphertext
      , indexCheckTestCase 0x0ff0 (hex "f3172ceffc3b3d997c85ccd5af1a950c") ciphertext
      , indexCheckTestCase 0x1000 (hex "e74b0b9731227fd37c0ec08a47ddd8b8") ciphertext ]
    index64 = testGroup "index64" $
      let ciphertext = rc4WithKey "0102030405060708" in
      [ indexCheckTestCase 0x0000 (hex "97ab8a1bf0afb96132f2f67258da15a8") ciphertext
      , indexCheckTestCase 0x0010 (hex "8263efdb45c4a18684ef87e6b19e5b09") ciphertext
      , indexCheckTestCase 0x00f0 (hex "9636ebc9841926f4f7d1f362bddf6e18") ciphertext
      , indexCheckTestCase 0x0100 (hex "d0a990ff2c05fef5b90373c9ff4b870a") ciphertext
      , indexCheckTestCase 0x01f0 (hex "73239f1db7f41d80b643c0c52518ec63") ciphertext
      , indexCheckTestCase 0x0200 (hex "163b319923a6bdb4527c626126703c0f") ciphertext
      , indexCheckTestCase 0x02f0 (hex "49d6c8af0f97144a87df21d91472f966") ciphertext
      , indexCheckTestCase 0x0300 (hex "44173a103b6616c5d5ad1cee40c863d0") ciphertext
      , indexCheckTestCase 0x03f0 (hex "273c9c4b27f322e4e716ef53a47de7a4") ciphertext
      , indexCheckTestCase 0x0400 (hex "c6d0e7b226259fa9023490b26167ad1d") ciphertext
      , indexCheckTestCase 0x05f0 (hex "1fe8986713f07c3d9ae1c163ff8cf9d3") ciphertext
      , indexCheckTestCase 0x0600 (hex "8369e1a965610be887fbd0c79162aafb") ciphertext
      , indexCheckTestCase 0x07f0 (hex "0a0127abb44484b9fbef5abcae1b579f") ciphertext
      , indexCheckTestCase 0x0800 (hex "c2cdadc6402e8ee866e1f37bdb47e42c") ciphertext
      , indexCheckTestCase 0x0bf0 (hex "26b51ea37df8e1d6f76fc3b66a7429b3") ciphertext
      , indexCheckTestCase 0x0c00 (hex "bc7683205d4f443dc1f29dda3315c87b") ciphertext
      , indexCheckTestCase 0x0ff0 (hex "d5fa5a3469d29aaaf83d23589db8c85b") ciphertext
      , indexCheckTestCase 0x1000 (hex "3fb46e2c8f0f068edce8cdcd7dfc5862") ciphertext ]
    index80 = testGroup "index80" $
      let ciphertext = rc4WithKey "0102030405060708090a" in
      [ indexCheckTestCase 0x0000 (hex "ede3b04643e586cc907dc21851709902") ciphertext
      , indexCheckTestCase 0x0010 (hex "03516ba78f413beb223aa5d4d2df6711") ciphertext
      , indexCheckTestCase 0x00f0 (hex "3cfd6cb58ee0fdde640176ad0000044d") ciphertext
      , indexCheckTestCase 0x0100 (hex "48532b21fb6079c9114c0ffd9c04a1ad") ciphertext
      , indexCheckTestCase 0x01f0 (hex "3e8cea98017109979084b1ef92f99d86") ciphertext
      , indexCheckTestCase 0x0200 (hex "e20fb49bdb337ee48b8d8dc0f4afeffe") ciphertext
      , indexCheckTestCase 0x02f0 (hex "5c2521eacd7966f15e056544bea0d315") ciphertext
      , indexCheckTestCase 0x0300 (hex "e067a7031931a246a6c3875d2f678acb") ciphertext
      , indexCheckTestCase 0x03f0 (hex "a64f70af88ae56b6f87581c0e23e6b08") ciphertext
      , indexCheckTestCase 0x0400 (hex "f449031de312814ec6f319291f4a0516") ciphertext
      , indexCheckTestCase 0x05f0 (hex "bdae85924b3cb1d0a2e33a30c6d79599") ciphertext
      , indexCheckTestCase 0x0600 (hex "8a0feddbac865a09bcd127fb562ed60a") ciphertext
      , indexCheckTestCase 0x07f0 (hex "b55a0a5b51a12a8be34899c3e047511a") ciphertext
      , indexCheckTestCase 0x0800 (hex "d9a09cea3ce75fe39698070317a71339") ciphertext
      , indexCheckTestCase 0x0bf0 (hex "552225ed1177f44584ac8cfa6c4eb5fc") ciphertext
      , indexCheckTestCase 0x0c00 (hex "7e82cbabfc95381b080998442129c2f8") ciphertext
      , indexCheckTestCase 0x0ff0 (hex "1f135ed14ce60a91369d2322bef25e3c") ciphertext
      , indexCheckTestCase 0x1000 (hex "08b6be45124a43e2eb77953f84dc8553") ciphertext ]
    index128 = testGroup "index128" $
      let ciphertext = rc4WithKey "0102030405060708090a0b0c0d0e0f10" in
      [ indexCheckTestCase 0x0000 (hex "9ac7cc9a609d1ef7b2932899cde41b97") ciphertext
      , indexCheckTestCase 0x0010 (hex "5248c4959014126a6e8a84f11d1a9e1c") ciphertext
      , indexCheckTestCase 0x00f0 (hex "065902e4b620f6cc36c8589f66432f2b") ciphertext
      , indexCheckTestCase 0x0100 (hex "d39d566bc6bce3010768151549f3873f") ciphertext
      , indexCheckTestCase 0x01f0 (hex "b6d1e6c4a5e4771cad79538df295fb11") ciphertext
      , indexCheckTestCase 0x0200 (hex "c68c1d5c559a974123df1dbc52a43b89") ciphertext
      , indexCheckTestCase 0x02f0 (hex "c5ecf88de897fd57fed301701b82a259") ciphertext
      , indexCheckTestCase 0x0300 (hex "eccbe13de1fcc91c11a0b26c0bc8fa4d") ciphertext
      , indexCheckTestCase 0x03f0 (hex "e7a72574f8782ae26aabcf9ebcd66065") ciphertext
      , indexCheckTestCase 0x0400 (hex "bdf0324e6083dcc6d3cedd3ca8c53c16") ciphertext
      , indexCheckTestCase 0x05f0 (hex "b40110c4190b5622a96116b0017ed297") ciphertext
      , indexCheckTestCase 0x0600 (hex "ffa0b514647ec04f6306b892ae661181") ciphertext
      , indexCheckTestCase 0x07f0 (hex "d03d1bc03cd33d70dff9fa5d71963ebd") ciphertext
      , indexCheckTestCase 0x0800 (hex "8a44126411eaa78bd51e8d87a8879bf5") ciphertext
      , indexCheckTestCase 0x0bf0 (hex "fabeb76028ade2d0e48722e46c4615a3") ciphertext
      , indexCheckTestCase 0x0c00 (hex "c05d88abd50357f935a63c59ee537623") ciphertext
      , indexCheckTestCase 0x0ff0 (hex "ff38265c1642c1abe8d3c2fe5e572bf8") ciphertext
      , indexCheckTestCase 0x1000 (hex "a36a4c301ae8ac13610ccbc12256cacc") ciphertext ]
    index192 = testGroup "index192" $
      let ciphertext = rc4WithKey "0102030405060708090a0b0c0d0e0f101112131415161718" in
      [ indexCheckTestCase 0x0000 (hex "0595e57fe5f0bb3c706edac8a4b2db11") ciphertext
      , indexCheckTestCase 0x0010 (hex "dfde31344a1af769c74f070aee9e2326") ciphertext
      , indexCheckTestCase 0x00f0 (hex "b06b9b1e195d13d8f4a7995c4553ac05") ciphertext
      , indexCheckTestCase 0x0100 (hex "6bd2378ec341c9a42f37ba79f88a32ff") ciphertext
      , indexCheckTestCase 0x01f0 (hex "e70bce1df7645adb5d2c4130215c3522") ciphertext
      , indexCheckTestCase 0x0200 (hex "9a5730c7fcb4c9af51ffda89c7f1ad22") ciphertext
      , indexCheckTestCase 0x02f0 (hex "0485055fd4f6f0d963ef5ab9a5476982") ciphertext
      , indexCheckTestCase 0x0300 (hex "591fc66bcda10e452b03d4551f6b62ac") ciphertext
      , indexCheckTestCase 0x03f0 (hex "2753cc83988afa3e1688a1d3b42c9a02") ciphertext
      , indexCheckTestCase 0x0400 (hex "93610d523d1d3f0062b3c2a3bbc7c7f0") ciphertext
      , indexCheckTestCase 0x05f0 (hex "96c248610aadedfeaf8978c03de8205a") ciphertext
      , indexCheckTestCase 0x0600 (hex "0e317b3d1c73b9e9a4688f296d133a19") ciphertext
      , indexCheckTestCase 0x07f0 (hex "bdf0e6c3cca5b5b9d533b69c56ada120") ciphertext
      , indexCheckTestCase 0x0800 (hex "88a218b6e2ece1e6246d44c759d19b10") ciphertext
      , indexCheckTestCase 0x0bf0 (hex "6866397e95c140534f94263421006e40") ciphertext
      , indexCheckTestCase 0x0c00 (hex "32cb0a1e9542c6b3b8b398abc3b0f1d5") ciphertext
      , indexCheckTestCase 0x0ff0 (hex "29a0b8aed54a132324c62e423f54b4c8") ciphertext
      , indexCheckTestCase 0x1000 (hex "3cb0f3b5020a98b82af9fe154484a168") ciphertext ]
    index256 = testGroup "index256" $
      let ciphertext = rc4WithKey "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" in
      [ indexCheckTestCase 0x0000 (hex "eaa6bd25880bf93d3f5d1e4ca2611d91") ciphertext
      , indexCheckTestCase 0x0010 (hex "cfa45c9f7e714b54bdfa80027cb14380") ciphertext
      , indexCheckTestCase 0x00f0 (hex "114ae344ded71b35f2e60febad727fd8") ciphertext
      , indexCheckTestCase 0x0100 (hex "02e1e7056b0f623900496422943e97b6") ciphertext
      , indexCheckTestCase 0x01f0 (hex "91cb93c787964e10d9527d999c6f936b") ciphertext
      , indexCheckTestCase 0x0200 (hex "49b18b42f8e8367cbeb5ef104ba1c7cd") ciphertext
      , indexCheckTestCase 0x02f0 (hex "87084b3ba700bade955610672745b374") ciphertext
      , indexCheckTestCase 0x0300 (hex "e7a7b9e9ec540d5ff43bdb12792d1b35") ciphertext
      , indexCheckTestCase 0x03f0 (hex "c799b596738f6b018c76c74b1759bd90") ciphertext
      , indexCheckTestCase 0x0400 (hex "7fec5bfd9f9b89ce6548309092d7e958") ciphertext
      , indexCheckTestCase 0x05f0 (hex "40f250b26d1f096a4afd4c340a588815") ciphertext
      , indexCheckTestCase 0x0600 (hex "3e34135c79db010200767651cf263073") ciphertext
      , indexCheckTestCase 0x07f0 (hex "f656abccf88dd827027b2ce917d464ec") ciphertext
      , indexCheckTestCase 0x0800 (hex "18b62503bfbc077fbabb98f20d98ab34") ciphertext
      , indexCheckTestCase 0x0bf0 (hex "8aed95ee5b0dcbfbef4eb21d3a3f52f9") ciphertext
      , indexCheckTestCase 0x0c00 (hex "625a1ab00ee39a5327346bddb01a9c18") ciphertext
      , indexCheckTestCase 0x0ff0 (hex "a13a7c79c7e119b5ab0296ab28c300b9") ciphertext
      , indexCheckTestCase 0x1000 (hex "f3e4c0a2e02d1d01f7f0a74618af2b48") ciphertext ]
    ietf40 = testGroup "ietf40" $
      let ciphertext = rc4WithKey "833222772a" in
      [ indexCheckTestCase 0x0000 (hex "80ad97bdc973df8a2e879e92a497efda") ciphertext
      , indexCheckTestCase 0x0010 (hex "20f060c2f2e5126501d3d4fea10d5fc0") ciphertext
      , indexCheckTestCase 0x00f0 (hex "faa148e99046181fec6b2085f3b20ed9") ciphertext
      , indexCheckTestCase 0x0100 (hex "f0daf5bab3d596839857846f73fbfe5a") ciphertext
      , indexCheckTestCase 0x01f0 (hex "1c7e2fc4639232fe297584b296996bc8") ciphertext
      , indexCheckTestCase 0x0200 (hex "3db9b249406cc8edffac55ccd322ba12") ciphertext
      , indexCheckTestCase 0x02f0 (hex "e4f9f7e0066154bbd125b745569bc897") ciphertext
      , indexCheckTestCase 0x0300 (hex "75d5ef262b44c41a9cf63ae14568e1b9") ciphertext
      , indexCheckTestCase 0x03f0 (hex "6da453dbf81e82334a3d8866cb50a1e3") ciphertext
      , indexCheckTestCase 0x0400 (hex "7828d074119cab5c22b294d7a9bfa0bb") ciphertext
      , indexCheckTestCase 0x05f0 (hex "adb89cea9a15fbe617295bd04b8ca05c") ciphertext
      , indexCheckTestCase 0x0600 (hex "6251d87fd4aaae9a7e4ad5c217d3f300") ciphertext
      , indexCheckTestCase 0x07f0 (hex "e7119bd6dd9b22afe8f89585432881e2") ciphertext
      , indexCheckTestCase 0x0800 (hex "785b60fd7ec4e9fcb6545f350d660fab") ciphertext
      , indexCheckTestCase 0x0bf0 (hex "afecc037fdb7b0838eb3d70bcd268382") ciphertext
      , indexCheckTestCase 0x0c00 (hex "dbc1a7b49d57358cc9fa6d61d73b7cf0") ciphertext
      , indexCheckTestCase 0x0ff0 (hex "6349d126a37afcba89794f9804914fdc") ciphertext
      , indexCheckTestCase 0x1000 (hex "bf42c3018c2f7c66bfde524975768115") ciphertext ]
    ietf56 = testGroup "ietf56" $
      let ciphertext = rc4WithKey "1910833222772a" in
      [ indexCheckTestCase 0x0000 (hex "bc9222dbd3274d8fc66d14ccbda6690b") ciphertext
      , indexCheckTestCase 0x0010 (hex "7ae627410c9a2be693df5bb7485a63e3") ciphertext
      , indexCheckTestCase 0x00f0 (hex "3f0931aa03defb300f060103826f2a64") ciphertext
      , indexCheckTestCase 0x0100 (hex "beaa9ec8d59bb68129f3027c96361181") ciphertext
      , indexCheckTestCase 0x01f0 (hex "74e04db46d28648d7dee8a0064b06cfe") ciphertext
      , indexCheckTestCase 0x0200 (hex "9b5e81c62fe023c55be42f87bbf932b8") ciphertext
      , indexCheckTestCase 0x02f0 (hex "ce178fc1826efecbc182f57999a46140") ciphertext
      , indexCheckTestCase 0x0300 (hex "8bdf55cd55061c06dba6be11de4a578a") ciphertext
      , indexCheckTestCase 0x03f0 (hex "626f5f4dce652501f3087d39c92cc349") ciphertext
      , indexCheckTestCase 0x0400 (hex "42daac6a8f9ab9a7fd137c6037825682") ciphertext
      , indexCheckTestCase 0x05f0 (hex "cc03fdb79192a207312f53f5d4dc33d9") ciphertext
      , indexCheckTestCase 0x0600 (hex "f70f14122a1c98a3155d28b8a0a8a41d") ciphertext
      , indexCheckTestCase 0x07f0 (hex "2a3a307ab2708a9c00fe0b42f9c2d6a1") ciphertext
      , indexCheckTestCase 0x0800 (hex "862617627d2261eab0b1246597ca0ae9") ciphertext
      , indexCheckTestCase 0x0bf0 (hex "55f877ce4f2e1ddbbf8e13e2cde0fdc8") ciphertext
      , indexCheckTestCase 0x0c00 (hex "1b1556cb935f173337705fbb5d501fc1") ciphertext
      , indexCheckTestCase 0x0ff0 (hex "ecd0e96602be7f8d5092816cccf2c2e9") ciphertext
      , indexCheckTestCase 0x1000 (hex "027881fab4993a1c262024a94fff3f61") ciphertext ]
    ietf64 = testGroup "ietf64" $
      let ciphertext = rc4WithKey "641910833222772a" in
      [ indexCheckTestCase 0x0000 (hex "bbf609de9413172d07660cb680716926") ciphertext
      , indexCheckTestCase 0x0010 (hex "46101a6dab43115d6c522b4fe93604a9") ciphertext
      , indexCheckTestCase 0x00f0 (hex "cbe1fff21c96f3eef61e8fe0542cbdf0") ciphertext
      , indexCheckTestCase 0x0100 (hex "347938bffa4009c512cfb4034b0dd1a7") ciphertext
      , indexCheckTestCase 0x01f0 (hex "7867a786d00a7147904d76ddf1e520e3") ciphertext
      , indexCheckTestCase 0x0200 (hex "8d3e9e1caefcccb3fbf8d18f64120b32") ciphertext
      , indexCheckTestCase 0x02f0 (hex "942337f8fd76f0fae8c52d7954810672") ciphertext
      , indexCheckTestCase 0x0300 (hex "b8548c10f51667f6e60e182fa19b30f7") ciphertext
      , indexCheckTestCase 0x03f0 (hex "0211c7c6190c9efd1237c34c8f2e06c4") ciphertext
      , indexCheckTestCase 0x0400 (hex "bda64f65276d2aacb8f90212203a808e") ciphertext
      , indexCheckTestCase 0x05f0 (hex "bd3820f732ffb53ec193e79d33e27c73") ciphertext
      , indexCheckTestCase 0x0600 (hex "d0168616861907d482e36cdac8cf5749") ciphertext
      , indexCheckTestCase 0x07f0 (hex "97b0f0f224b2d2317114808fb03af7a0") ciphertext
      , indexCheckTestCase 0x0800 (hex "e59616e469787939a063ceea9af956d1") ciphertext
      , indexCheckTestCase 0x0bf0 (hex "c47e0dc1660919c11101208f9e69aa1f") ciphertext
      , indexCheckTestCase 0x0c00 (hex "5ae4f12896b8379a2aad89b5b553d6b0") ciphertext
      , indexCheckTestCase 0x0ff0 (hex "6b6b098d0c293bc2993d80bf0518b6d9") ciphertext
      , indexCheckTestCase 0x1000 (hex "8170cc3ccd92a698621b939dd38fe7b9") ciphertext ]
    ietf80 = testGroup "ietf80" $
      let ciphertext = rc4WithKey "8b37641910833222772a" in
      [ indexCheckTestCase 0x0000 (hex "ab65c26eddb287600db2fda10d1e605c") ciphertext
      , indexCheckTestCase 0x0010 (hex "bb759010c29658f2c72d93a2d16d2930") ciphertext
      , indexCheckTestCase 0x00f0 (hex "b901e8036ed1c383cd3c4c4dd0a6ab05") ciphertext
      , indexCheckTestCase 0x0100 (hex "3d25ce4922924c55f064943353d78a6c") ciphertext
      , indexCheckTestCase 0x01f0 (hex "12c1aa44bbf87e75e611f69b2c38f49b") ciphertext
      , indexCheckTestCase 0x0200 (hex "28f2b3434b65c09877470044c6ea170d") ciphertext
      , indexCheckTestCase 0x02f0 (hex "bd9ef822de5288196134cf8af7839304") ciphertext
      , indexCheckTestCase 0x0300 (hex "67559c23f052158470a296f725735a32") ciphertext
      , indexCheckTestCase 0x03f0 (hex "8bab26fbc2c12b0f13e2ab185eabf241") ciphertext
      , indexCheckTestCase 0x0400 (hex "31185a6d696f0cfa9b42808b38e132a2") ciphertext
      , indexCheckTestCase 0x05f0 (hex "564d3dae183c5234c8af1e51061c44b5") ciphertext
      , indexCheckTestCase 0x0600 (hex "3c0778a7b5f72d3c23a3135c7d67b9f4") ciphertext
      , indexCheckTestCase 0x07f0 (hex "f34369890fcf16fb517dcaae4463b2dd") ciphertext
      , indexCheckTestCase 0x0800 (hex "02f31c81e8200731b899b028e791bfa7") ciphertext
      , indexCheckTestCase 0x0bf0 (hex "72da646283228c14300853701795616f") ciphertext
      , indexCheckTestCase 0x0c00 (hex "4e0a8c6f7934a788e2265e81d6d0c8f4") ciphertext
      , indexCheckTestCase 0x0ff0 (hex "438dd5eafea0111b6f36b4b938da2a68") ciphertext
      , indexCheckTestCase 0x1000 (hex "5f6bfc73815874d97100f086979357d8") ciphertext ]
    ietf128 = testGroup "ietf128" $
      let ciphertext = rc4WithKey "ebb46227c6cc8b37641910833222772a" in
      [ indexCheckTestCase 0x0000 (hex "720c94b63edf44e131d950ca211a5a30") ciphertext
      , indexCheckTestCase 0x0010 (hex "c366fdeacf9ca80436be7c358424d20b") ciphertext
      , indexCheckTestCase 0x00f0 (hex "b3394a40aabf75cba42282ef25a0059f") ciphertext
      , indexCheckTestCase 0x0100 (hex "4847d81da4942dbc249defc48c922b9f") ciphertext
      , indexCheckTestCase 0x01f0 (hex "08128c469f275342adda202b2b58da95") ciphertext
      , indexCheckTestCase 0x0200 (hex "970dacef40ad98723bac5d6955b81761") ciphertext
      , indexCheckTestCase 0x02f0 (hex "3cb89993b07b0ced93de13d2a11013ac") ciphertext
      , indexCheckTestCase 0x0300 (hex "ef2d676f1545c2c13dc680a02f4adbfe") ciphertext
      , indexCheckTestCase 0x03f0 (hex "b60595514f24bc9fe522a6cad7393644") ciphertext
      , indexCheckTestCase 0x0400 (hex "b515a8c5011754f59003058bdb81514e") ciphertext
      , indexCheckTestCase 0x05f0 (hex "3c70047e8cbc038e3b9820db601da495") ciphertext
      , indexCheckTestCase 0x0600 (hex "1175da6ee756de46a53e2b075660b770") ciphertext
      , indexCheckTestCase 0x07f0 (hex "00a542bba02111cc2c65b38ebdba587e") ciphertext
      , indexCheckTestCase 0x0800 (hex "5865fdbb5b48064104e830b380f2aede") ciphertext
      , indexCheckTestCase 0x0bf0 (hex "34b21ad2ad44e999db2d7f0863f0d9b6") ciphertext
      , indexCheckTestCase 0x0c00 (hex "84a9218fc36e8a5f2ccfbeae53a27d25") ciphertext
      , indexCheckTestCase 0x0ff0 (hex "a2221a11b833ccb498a59540f0545f4a") ciphertext
      , indexCheckTestCase 0x1000 (hex "5bbeb4787d59e5373fdbea6c6f75c29b") ciphertext ]
    ietf192 = testGroup "ietf192" $
      let ciphertext = rc4WithKey "c109163908ebe51debb46227c6cc8b37641910833222772a" in
      [ indexCheckTestCase 0x0000 (hex "54b64e6b5a20b5e2ec84593dc7989da7") ciphertext
      , indexCheckTestCase 0x0010 (hex "c135eee237a85465ff97dc03924f45ce") ciphertext
      , indexCheckTestCase 0x00f0 (hex "cfcc922fb4a14ab45d6175aabbf2d201") ciphertext
      , indexCheckTestCase 0x0100 (hex "837b87e2a446ad0ef798acd02b94124f") ciphertext
      , indexCheckTestCase 0x01f0 (hex "17a6dbd664926a0636b3f4c37a4f4694") ciphertext
      , indexCheckTestCase 0x0200 (hex "4a5f9f26aeeed4d4a25f632d305233d9") ciphertext
      , indexCheckTestCase 0x02f0 (hex "80a3d01ef00c8e9a4209c17f4eeb358c") ciphertext
      , indexCheckTestCase 0x0300 (hex "d15e7d5ffaaabc0207bf200a117793a2") ciphertext
      , indexCheckTestCase 0x03f0 (hex "349682bf588eaa52d0aa1560346aeafa") ciphertext
      , indexCheckTestCase 0x0400 (hex "f5854cdb76c889e3ad63354e5f7275e3") ciphertext
      , indexCheckTestCase 0x05f0 (hex "532c7ceccb39df3236318405a4b1279c") ciphertext
      , indexCheckTestCase 0x0600 (hex "baefe6d9ceb651842260e0d1e05e3b90") ciphertext
      , indexCheckTestCase 0x07f0 (hex "e82d8c6db54e3c633f581c952ba04207") ciphertext
      , indexCheckTestCase 0x0800 (hex "4b16e50abd381bd70900a9cd9a62cb23") ciphertext
      , indexCheckTestCase 0x0bf0 (hex "3682ee33bd148bd9f58656cd8f30d9fb") ciphertext
      , indexCheckTestCase 0x0c00 (hex "1e5a0b8475045d9b20b2628624edfd9e") ciphertext
      , indexCheckTestCase 0x0ff0 (hex "63edd684fb826282fe528f9c0e9237bc") ciphertext
      , indexCheckTestCase 0x1000 (hex "e4dd2e98d6960fae0b43545456743391") ciphertext ]
    ietf256 = testGroup "ietf256" $
      let ciphertext = rc4WithKey "1ada31d5cf688221c109163908ebe51debb46227c6cc8b37641910833222772a" in
      [ indexCheckTestCase 0x0000 (hex "dd5bcb0018e922d494759d7c395d02d3") ciphertext
      , indexCheckTestCase 0x0010 (hex "c8446f8f77abf737685353eb89a1c9eb") ciphertext
      , indexCheckTestCase 0x00f0 (hex "af3e30f9c095045938151575c3fb9098") ciphertext
      , indexCheckTestCase 0x0100 (hex "f8cb6274db99b80b1d2012a98ed48f0e") ciphertext
      , indexCheckTestCase 0x01f0 (hex "25c3005a1cb85de076259839ab7198ab") ciphertext
      , indexCheckTestCase 0x0200 (hex "9dcbc183e8cb994b727b75be3180769c") ciphertext
      , indexCheckTestCase 0x02f0 (hex "a1d3078dfa9169503ed9d4491dee4eb2") ciphertext
      , indexCheckTestCase 0x0300 (hex "8514a5495858096f596e4bcd66b10665") ciphertext
      , indexCheckTestCase 0x03f0 (hex "5f40d59ec1b03b33738efa60b2255d31") ciphertext
      , indexCheckTestCase 0x0400 (hex "3477c7f764a41baceff90bf14f92b7cc") ciphertext
      , indexCheckTestCase 0x05f0 (hex "ac4e95368d99b9eb78b8da8f81ffa795") ciphertext
      , indexCheckTestCase 0x0600 (hex "8c3c13f8c2388bb73f38576e65b7c446") ciphertext
      , indexCheckTestCase 0x07f0 (hex "13c4b9c1dfb66579eddd8a280b9f7316") ciphertext
      , indexCheckTestCase 0x0800 (hex "ddd27820550126698efaadc64b64f66e") ciphertext
      , indexCheckTestCase 0x0bf0 (hex "f08f2e66d28ed143f3a237cf9de73559") ciphertext
      , indexCheckTestCase 0x0c00 (hex "9ea36c525531b880ba124334f57b0b70") ciphertext
      , indexCheckTestCase 0x0ff0 (hex "d5a39e3dfcc50280bac4a6b5aa0dca7d") ciphertext
      , indexCheckTestCase 0x1000 (hex "370b1c1fe655916d97fd0d47ca1d72b8") ciphertext ]

indexCheckTestCase :: Int -> ByteString -> Either [Error] ByteString -> TestTree
indexCheckTestCase index expected actual = testCase (show index) $
  assertIsRightAndHasAtIndex index expected actual

assertIsRightAndHasAtIndex :: Int -> ByteString -> Either [Error] ByteString -> Assertion
assertIsRightAndHasAtIndex index expected actual =
  case actual of
    Left es -> assertFailure ("expected: Right _\n but got: Left " ++ show es)
    Right c ->
      let actual = slice index (ByteString.length expected) c in
      expected == actual @? "expected: Right " ++ ellipsize index expected
                            ++ "\n but got: Right " ++ ellipsize index actual

slice :: Int -> Int -> ByteString -> ByteString
slice start length = ByteString.take length . ByteString.drop start

ellipsize :: Int -> ByteString -> String
ellipsize n s = concat [if n == 0 then "" else "...", showHex s, "..."]
