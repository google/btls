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

{-# LANGUAGE OverloadedStrings #-}

module Data.Digest.SHA2Tests (tests) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as Lazy (ByteString)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit ((@?=), testCase)
import Test.Tasty.SmallCheck (testProperty)

import Data.Digest (hash, sha224, sha256, sha384, sha512)
import Data.Digest.HashTests
  (hashTestCase, hexDigest, testAgainstCoreutils, testAgainstOpenSSL)

tests :: TestTree
tests = testGroup "SHA-2"
  [ testNISTExamples
  , testGoExamples
  , testCoreutilsConformance
  , testOpenSSLConformance ]

-- | SHA-2 example vectors from
-- https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values.
testNISTExamples = testGroup "NIST examples"
  [ testNISTSHA224
  , testNISTSHA256
  , testNISTSHA384
  , testNISTSHA512 ]

testNISTSHA224 = testGroup "SHA-224"
  [ testCase "one-block" $ hash sha224 "abc" @?= hexDigest "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
  , testCase "two-block" $ hash sha224 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" @?= hexDigest "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525" ]

testNISTSHA256 = testGroup "SHA-256"
  [ testCase "one-block" $ hash sha256 "abc" @?= hexDigest "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  , testCase "two-block" $ hash sha256 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" @?= hexDigest "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" ]

testNISTSHA384 = testGroup "SHA-384"
  [ testCase "one-block" $ hash sha384 "abc" @?= hexDigest "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
  , testCase "two-block" $ hash sha384 "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" @?= hexDigest "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039" ]

testNISTSHA512 = testGroup "SHA-512"
  [ testCase "one-block" $ hash sha512 "abc" @?= hexDigest "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
  , testCase "two-block" $ hash sha512 "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" @?= hexDigest "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909" ]

-- | Test vectors used to test the Go SHA-2 implementations.
testGoExamples = testGroup "Go tests"
  [ testGoSHA224
  , testGoSHA256
  , testGoSHA384
  , testGoSHA512 ]

sha224TestCase, sha256TestCase, sha384TestCase, sha512TestCase ::
  Lazy.ByteString -> ByteString -> TestTree
sha224TestCase = hashTestCase sha224
sha256TestCase = hashTestCase sha256
sha384TestCase = hashTestCase sha384
sha512TestCase = hashTestCase sha512

testGoSHA224 = testGroup "SHA-224"
  [ sha224TestCase "" "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
  , sha224TestCase "a" "abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5"
  , sha224TestCase "ab" "db3cda86d4429a1d39c148989566b38f7bda0156296bd364ba2f878b"
  , sha224TestCase "abc" "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
  , sha224TestCase "abcd" "a76654d8e3550e9a2d67a0eeb6c67b220e5885eddd3fde135806e601"
  , sha224TestCase "abcde" "bdd03d560993e675516ba5a50638b6531ac2ac3d5847c61916cfced6"
  , sha224TestCase "abcdef" "7043631cb415556a275a4ebecb802c74ee9f6153908e1792a90b6a98"
  , sha224TestCase "abcdefg" "d1884e711701ad81abe0c77a3b0ea12e19ba9af64077286c72fc602d"
  , sha224TestCase "abcdefgh" "17eb7d40f0356f8598e89eafad5f6c759b1f822975d9c9b737c8a517"
  , sha224TestCase "abcdefghi" "aeb35915346c584db820d2de7af3929ffafef9222a9bcb26516c7334"
  , sha224TestCase "abcdefghij" "d35e1e5af29ddb0d7e154357df4ad9842afee527c689ee547f753188"
  , sha224TestCase "Discard medicine more than two years old." "19297f1cef7ddc8a7e947f5c5a341e10f7245045e425db67043988d7"
  , sha224TestCase "He who has a shady past knows that nice guys finish last." "0f10c2eb436251f777fbbd125e260d36aecf180411726c7c885f599a"
  , sha224TestCase "I wouldn't marry him with a ten foot pole." "4d1842104919f314cad8a3cd20b3cba7e8ed3e7abed62b57441358f6"
  , sha224TestCase "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave" "a8ba85c6fe0c48fbffc72bbb2f03fcdbc87ae2dc7a56804d1590fb3b"
  , sha224TestCase "The days of the digital watch are numbered.  -Tom Stoppard" "5543fbab26e67e8885b1a852d567d1cb8b9bfe42e0899584c50449a9"
  , sha224TestCase "Nepal premier won't resign." "65ca107390f5da9efa05d28e57b221657edc7e43a9a18fb15b053ddb"
  , sha224TestCase "For every action there is an equal and opposite government program." "84953962be366305a9cc9b5cd16ed019edc37ac96c0deb3e12cca116"
  , sha224TestCase "His money is twice tainted: 'taint yours and 'taint mine." "35a189ce987151dfd00b3577583cc6a74b9869eecf894459cb52038d"
  , sha224TestCase "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977" "2fc333713983edfd4ef2c0da6fb6d6415afb94987c91e4069eb063e6"
  , sha224TestCase "It's a tiny change to the code and not completely disgusting. - Bob Manchek" "cbe32d38d577a1b355960a4bc3c659c2dc4670859a19777a875842c4"
  , sha224TestCase "size:  a.out:  bad magic" "a2dc118ce959e027576413a7b440c875cdc8d40df9141d6ef78a57e1"
  , sha224TestCase "The major problem is with sendmail.  -Mark Horton" "d10787e24052bcff26dc484787a54ed819e4e4511c54890ee977bf81"
  , sha224TestCase "Give me a rock, paper and scissors and I will move the world.  CCFestoon" "62efcf16ab8a893acdf2f348aaf06b63039ff1bf55508c830532c9fb"
  , sha224TestCase "If the enemy is within range, then so are you." "3e9b7e4613c59f58665104c5fa86c272db5d3a2ff30df5bb194a5c99"
  , sha224TestCase "It's well we cannot hear the screams/That we create in others' dreams." "5999c208b8bdf6d471bb7c359ac5b829e73a8211dff686143a4e7f18"
  , sha224TestCase "You remind me of a TV show, but that's all right: I watch it anyway." "3b2d67ff54eabc4ef737b14edf87c64280ef582bcdf2a6d56908b405"
  , sha224TestCase "C is as portable as Stonehedge!!" "d0733595d20e4d3d6b5c565a445814d1bbb2fd08b9a3b8ffb97930c6"
  , sha224TestCase "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley" "43fb8aeed8a833175c9295c1165415f98c866ef08a4922959d673507"
  , sha224TestCase "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule" "ec18e66e93afc4fb1604bc2baedbfd20b44c43d76e65c0996d7851c6"
  , sha224TestCase "How can you write a big system without C++?  -Paul Glick" "86ed2eaa9c75ba98396e5c9fb2f679ecf0ea2ed1e0ee9ceecb4a9332" ]

testGoSHA256 = testGroup "SHA-256"
  [ sha256TestCase "" "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  , sha256TestCase "a" "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
  , sha256TestCase "ab" "fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603"
  , sha256TestCase "abc" "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  , sha256TestCase "abcd" "88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589"
  , sha256TestCase "abcde" "36bbe50ed96841d10443bcb670d6554f0a34b761be67ec9c4a8ad2c0c44ca42c"
  , sha256TestCase "abcdef" "bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721"
  , sha256TestCase "abcdefg" "7d1a54127b222502f5b79b5fb0803061152a44f92b37e23c6527baf665d4da9a"
  , sha256TestCase "abcdefgh" "9c56cc51b374c3ba189210d5b6d4bf57790d351c96c47c02190ecf1e430635ab"
  , sha256TestCase "abcdefghi" "19cc02f26df43cc571bc9ed7b0c4d29224a3ec229529221725ef76d021c8326f"
  , sha256TestCase "abcdefghij" "72399361da6a7754fec986dca5b7cbaf1c810a28ded4abaf56b2106d06cb78b0"
  , sha256TestCase "Discard medicine more than two years old." "a144061c271f152da4d151034508fed1c138b8c976339de229c3bb6d4bbb4fce"
  , sha256TestCase "He who has a shady past knows that nice guys finish last." "6dae5caa713a10ad04b46028bf6dad68837c581616a1589a265a11288d4bb5c4"
  , sha256TestCase "I wouldn't marry him with a ten foot pole." "ae7a702a9509039ddbf29f0765e70d0001177914b86459284dab8b348c2dce3f"
  , sha256TestCase "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave" "6748450b01c568586715291dfa3ee018da07d36bb7ea6f180c1af6270215c64f"
  , sha256TestCase "The days of the digital watch are numbered.  -Tom Stoppard" "14b82014ad2b11f661b5ae6a99b75105c2ffac278cd071cd6c05832793635774"
  , sha256TestCase "Nepal premier won't resign." "7102cfd76e2e324889eece5d6c41921b1e142a4ac5a2692be78803097f6a48d8"
  , sha256TestCase "For every action there is an equal and opposite government program." "23b1018cd81db1d67983c5f7417c44da9deb582459e378d7a068552ea649dc9f"
  , sha256TestCase "His money is twice tainted: 'taint yours and 'taint mine." "8001f190dfb527261c4cfcab70c98e8097a7a1922129bc4096950e57c7999a5a"
  , sha256TestCase "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977" "8c87deb65505c3993eb24b7a150c4155e82eee6960cf0c3a8114ff736d69cad5"
  , sha256TestCase "It's a tiny change to the code and not completely disgusting. - Bob Manchek" "bfb0a67a19cdec3646498b2e0f751bddc41bba4b7f30081b0b932aad214d16d7"
  , sha256TestCase "size:  a.out:  bad magic" "7f9a0b9bf56332e19f5a0ec1ad9c1425a153da1c624868fda44561d6b74daf36"
  , sha256TestCase "The major problem is with sendmail.  -Mark Horton" "b13f81b8aad9e3666879af19886140904f7f429ef083286195982a7588858cfc"
  , sha256TestCase "Give me a rock, paper and scissors and I will move the world.  CCFestoon" "b26c38d61519e894480c70c8374ea35aa0ad05b2ae3d6674eec5f52a69305ed4"
  , sha256TestCase "If the enemy is within range, then so are you." "049d5e26d4f10222cd841a119e38bd8d2e0d1129728688449575d4ff42b842c1"
  , sha256TestCase "It's well we cannot hear the screams/That we create in others' dreams." "0e116838e3cc1c1a14cd045397e29b4d087aa11b0853fc69ec82e90330d60949"
  , sha256TestCase "You remind me of a TV show, but that's all right: I watch it anyway." "4f7d8eb5bcf11de2a56b971021a444aa4eafd6ecd0f307b5109e4e776cd0fe46"
  , sha256TestCase "C is as portable as Stonehedge!!" "61c0cc4c4bd8406d5120b3fb4ebc31ce87667c162f29468b3c779675a85aebce"
  , sha256TestCase "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley" "1fb2eb3688093c4a3f80cd87a5547e2ce940a4f923243a79a2a1e242220693ac"
  , sha256TestCase "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule" "395585ce30617b62c80b93e8208ce866d4edc811a177fdb4b82d3911d8696423"
  , sha256TestCase "How can you write a big system without C++?  -Paul Glick" "4f9b189a13d030838269dce846b16a1ce9ce81fe63e65de2f636863336a98fe6" ]

testGoSHA384 = testGroup "SHA-384"
  [ sha384TestCase "" "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
  , sha384TestCase "a" "54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31"
  , sha384TestCase "ab" "c7be03ba5bcaa384727076db0018e99248e1a6e8bd1b9ef58a9ec9dd4eeebb3f48b836201221175befa74ddc3d35afdd"
  , sha384TestCase "abc" "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
  , sha384TestCase "abcd" "1165b3406ff0b52a3d24721f785462ca2276c9f454a116c2b2ba20171a7905ea5a026682eb659c4d5f115c363aa3c79b"
  , sha384TestCase "abcde" "4c525cbeac729eaf4b4665815bc5db0c84fe6300068a727cf74e2813521565abc0ec57a37ee4d8be89d097c0d2ad52f0"
  , sha384TestCase "abcdef" "c6a4c65b227e7387b9c3e839d44869c4cfca3ef583dea64117859b808c1e3d8ae689e1e314eeef52a6ffe22681aa11f5"
  , sha384TestCase "abcdefg" "9f11fc131123f844c1226f429b6a0a6af0525d9f40f056c7fc16cdf1b06bda08e302554417a59fa7dcf6247421959d22"
  , sha384TestCase "abcdefgh" "9000cd7cada59d1d2eb82912f7f24e5e69cc5517f68283b005fa27c285b61e05edf1ad1a8a9bded6fd29eb87d75ad806"
  , sha384TestCase "abcdefghi" "ef54915b60cf062b8dd0c29ae3cad69abe6310de63ac081f46ef019c5c90897caefd79b796cfa81139788a260ded52df"
  , sha384TestCase "abcdefghij" "a12070030a02d86b0ddacd0d3a5b598344513d0a051e7355053e556a0055489c1555399b03342845c4adde2dc44ff66c"
  , sha384TestCase "Discard medicine more than two years old." "86f58ec2d74d1b7f8eb0c2ff0967316699639e8d4eb129de54bdf34c96cdbabe200d052149f2dd787f43571ba74670d4"
  , sha384TestCase "He who has a shady past knows that nice guys finish last." "ae4a2b639ca9bfa04b1855d5a05fe7f230994f790891c6979103e2605f660c4c1262a48142dcbeb57a1914ba5f7c3fa7"
  , sha384TestCase "I wouldn't marry him with a ten foot pole." "40ae213df6436eca952aa6841886fcdb82908ef1576a99c8f49bb9dd5023169f7c53035abdda0b54c302f4974e2105e7"
  , sha384TestCase "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave" "e7cf8b873c9bc950f06259aa54309f349cefa72c00d597aebf903e6519a50011dfe355afff064a10701c705693848df9"
  , sha384TestCase "The days of the digital watch are numbered.  -Tom Stoppard" "c3d4f0f4047181c7d39d34703365f7bf70207183caf2c2f6145f04da895ef69124d9cdeb635da636c3a474e61024e29b"
  , sha384TestCase "Nepal premier won't resign." "a097aab567e167d5cf93676ed73252a69f9687cb3179bb2d27c9878119e94bf7b7c4b58dc90582edfaf66e11388ed714"
  , sha384TestCase "For every action there is an equal and opposite government program." "5026ca45c41fc64712eb65065da92f6467541c78f8966d3fe2c8e3fb769a3ec14215f819654b47bd64f7f0eac17184f3"
  , sha384TestCase "His money is twice tainted: 'taint yours and 'taint mine." "ac1cc0f5ac8d5f5514a7b738ac322b7fb52a161b449c3672e9b6a6ad1a5e4b26b001cf3bad24c56598676ca17d4b445a"
  , sha384TestCase "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977" "722d10c5de371ec0c8c4b5247ac8a5f1d240d68c73f8da13d8b25f0166d6f309bf9561979a111a0049405771d201941a"
  , sha384TestCase "It's a tiny change to the code and not completely disgusting. - Bob Manchek" "dc2d3ea18bfa10549c63bf2b75b39b5167a80c12aff0e05443168ea87ff149fb0eda5e0bd234eb5d48c7d02ffc5807f1"
  , sha384TestCase "size:  a.out:  bad magic" "1d67c969e2a945ae5346d2139760261504d4ba164c522443afe19ef3e29b152a4c52445489cfc9d7215e5a450e8e1e4e"
  , sha384TestCase "The major problem is with sendmail.  -Mark Horton" "5ff8e075e465646e7b73ef36d812c6e9f7d60fa6ea0e533e5569b4f73cde53cdd2cc787f33540af57cca3fe467d32fe0"
  , sha384TestCase "Give me a rock, paper and scissors and I will move the world.  CCFestoon" "5bd0a997a67c9ae1979a894eb0cde403dde003c9b6f2c03cf21925c42ff4e1176e6df1ca005381612ef18457b9b7ec3b"
  , sha384TestCase "If the enemy is within range, then so are you." "1eee6da33e7e54fc5be52ae23b94b16ba4d2a947ae4505c6a3edfc7401151ea5205ac01b669b56f27d8ef7f175ed7762"
  , sha384TestCase "It's well we cannot hear the screams/That we create in others' dreams." "76b06e9dea66bfbb1a96029426dc0dfd7830bd297eb447ff5358d94a87cd00c88b59df2493fef56ecbb5231073892ea9"
  , sha384TestCase "You remind me of a TV show, but that's all right: I watch it anyway." "12acaf21452cff586143e3f5db0bfdf7802c057e1adf2a619031c4e1b0ccc4208cf6cef8fe722bbaa2fb46a30d9135d8"
  , sha384TestCase "C is as portable as Stonehedge!!" "0fc23d7f4183efd186f0bc4fc5db867e026e2146b06cb3d52f4bdbd57d1740122caa853b41868b197b2ac759db39df88"
  , sha384TestCase "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley" "bc805578a7f85d34a86a32976e1c34fe65cf815186fbef76f46ef99cda10723f971f3f1464d488243f5e29db7488598d"
  , sha384TestCase "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule" "b23918399a12ebf4431559eec3813eaf7412e875fd7464f16d581e473330842d2e96c6be49a7ce3f9bb0b8bc0fcbe0fe"
  , sha384TestCase "How can you write a big system without C++?  -Paul Glick" "1764b700eb1ead52a2fc33cc28975c2180f1b8faa5038d94cffa8d78154aab16e91dd787e7b0303948ebed62561542c8" ]

testGoSHA512 = testGroup "SHA-512"
  [ sha512TestCase "" "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
  , sha512TestCase "a" "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75"
  , sha512TestCase "ab" "2d408a0717ec188158278a796c689044361dc6fdde28d6f04973b80896e1823975cdbf12eb63f9e0591328ee235d80e9b5bf1aa6a44f4617ff3caf6400eb172d"
  , sha512TestCase "abc" "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
  , sha512TestCase "abcd" "d8022f2060ad6efd297ab73dcc5355c9b214054b0d1776a136a669d26a7d3b14f73aa0d0ebff19ee333368f0164b6419a96da49e3e481753e7e96b716bdccb6f"
  , sha512TestCase "abcde" "878ae65a92e86cac011a570d4c30a7eaec442b85ce8eca0c2952b5e3cc0628c2e79d889ad4d5c7c626986d452dd86374b6ffaa7cd8b67665bef2289a5c70b0a1"
  , sha512TestCase "abcdef" "e32ef19623e8ed9d267f657a81944b3d07adbb768518068e88435745564e8d4150a0a703be2a7d88b61e3d390c2bb97e2d4c311fdc69d6b1267f05f59aa920e7"
  , sha512TestCase "abcdefg" "d716a4188569b68ab1b6dfac178e570114cdf0ea3a1cc0e31486c3e41241bc6a76424e8c37ab26f096fc85ef9886c8cb634187f4fddff645fb099f1ff54c6b8c"
  , sha512TestCase "abcdefgh" "a3a8c81bc97c2560010d7389bc88aac974a104e0e2381220c6e084c4dccd1d2d17d4f86db31c2a851dc80e6681d74733c55dcd03dd96f6062cdda12a291ae6ce"
  , sha512TestCase "abcdefghi" "f22d51d25292ca1d0f68f69aedc7897019308cc9db46efb75a03dd494fc7f126c010e8ade6a00a0c1a5f1b75d81e0ed5a93ce98dc9b833db7839247b1d9c24fe"
  , sha512TestCase "abcdefghij" "ef6b97321f34b1fea2169a7db9e1960b471aa13302a988087357c520be957ca119c3ba68e6b4982c019ec89de3865ccf6a3cda1fe11e59f98d99f1502c8b9745"
  , sha512TestCase "Discard medicine more than two years old." "2210d99af9c8bdecda1b4beff822136753d8342505ddce37f1314e2cdbb488c6016bdaa9bd2ffa513dd5de2e4b50f031393d8ab61f773b0e0130d7381e0f8a1d"
  , sha512TestCase "He who has a shady past knows that nice guys finish last." "a687a8985b4d8d0a24f115fe272255c6afaf3909225838546159c1ed685c211a203796ae8ecc4c81a5b6315919b3a64f10713da07e341fcdbb08541bf03066ce"
  , sha512TestCase "I wouldn't marry him with a ten foot pole." "8ddb0392e818b7d585ab22769a50df660d9f6d559cca3afc5691b8ca91b8451374e42bcdabd64589ed7c91d85f626596228a5c8572677eb98bc6b624befb7af8"
  , sha512TestCase "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave" "26ed8f6ca7f8d44b6a8a54ae39640fa8ad5c673f70ee9ce074ba4ef0d483eea00bab2f61d8695d6b34df9c6c48ae36246362200ed820448bdc03a720366a87c6"
  , sha512TestCase "The days of the digital watch are numbered.  -Tom Stoppard" "e5a14bf044be69615aade89afcf1ab0389d5fc302a884d403579d1386a2400c089b0dbb387ed0f463f9ee342f8244d5a38cfbc0e819da9529fbff78368c9a982"
  , sha512TestCase "Nepal premier won't resign." "420a1faa48919e14651bed45725abe0f7a58e0f099424c4e5a49194946e38b46c1f8034b18ef169b2e31050d1648e0b982386595f7df47da4b6fd18e55333015"
  , sha512TestCase "For every action there is an equal and opposite government program." "d926a863beadb20134db07683535c72007b0e695045876254f341ddcccde132a908c5af57baa6a6a9c63e6649bba0c213dc05fadcf9abccea09f23dcfb637fbe"
  , sha512TestCase "His money is twice tainted: 'taint yours and 'taint mine." "9a98dd9bb67d0da7bf83da5313dff4fd60a4bac0094f1b05633690ffa7f6d61de9a1d4f8617937d560833a9aaa9ccafe3fd24db418d0e728833545cadd3ad92d"
  , sha512TestCase "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977" "d7fde2d2351efade52f4211d3746a0780a26eec3df9b2ed575368a8a1c09ec452402293a8ea4eceb5a4f60064ea29b13cdd86918cd7a4faf366160b009804107"
  , sha512TestCase "It's a tiny change to the code and not completely disgusting. - Bob Manchek" "b0f35ffa2697359c33a56f5c0cf715c7aeed96da9905ca2698acadb08fbc9e669bf566b6bd5d61a3e86dc22999bcc9f2224e33d1d4f32a228cf9d0349e2db518"
  , sha512TestCase "size:  a.out:  bad magic" "3d2e5f91778c9e66f7e061293aaa8a8fc742dd3b2e4f483772464b1144189b49273e610e5cccd7a81a19ca1fa70f16b10f1a100a4d8c1372336be8484c64b311"
  , sha512TestCase "The major problem is with sendmail.  -Mark Horton" "b2f68ff58ac015efb1c94c908b0d8c2bf06f491e4de8e6302c49016f7f8a33eac3e959856c7fddbc464de618701338a4b46f76dbfaf9a1e5262b5f40639771c7"
  , sha512TestCase "Give me a rock, paper and scissors and I will move the world.  CCFestoon" "d8c92db5fdf52cf8215e4df3b4909d29203ff4d00e9ad0b64a6a4e04dec5e74f62e7c35c7fb881bd5de95442123df8f57a489b0ae616bd326f84d10021121c57"
  , sha512TestCase "If the enemy is within range, then so are you." "19a9f8dc0a233e464e8566ad3ca9b91e459a7b8c4780985b015776e1bf239a19bc233d0556343e2b0a9bc220900b4ebf4f8bdf89ff8efeaf79602d6849e6f72e"
  , sha512TestCase "It's well we cannot hear the screams/That we create in others' dreams." "00b4c41f307bde87301cdc5b5ab1ae9a592e8ecbb2021dd7bc4b34e2ace60741cc362560bec566ba35178595a91932b8d5357e2c9cec92d393b0fa7831852476"
  , sha512TestCase "You remind me of a TV show, but that's all right: I watch it anyway." "91eccc3d5375fd026e4d6787874b1dce201cecd8a27dbded5065728cb2d09c58a3d467bb1faf353bf7ba567e005245d5321b55bc344f7c07b91cb6f26c959be7"
  , sha512TestCase "C is as portable as Stonehedge!!" "fabbbe22180f1f137cfdc9556d2570e775d1ae02a597ded43a72a40f9b485d500043b7be128fb9fcd982b83159a0d99aa855a9e7cc4240c00dc01a9bdf8218d7"
  , sha512TestCase "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley" "2ecdec235c1fa4fc2a154d8fba1dddb8a72a1ad73838b51d792331d143f8b96a9f6fcb0f34d7caa351fe6d88771c4f105040e0392f06e0621689d33b2f3ba92e"
  , sha512TestCase "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule" "7ad681f6f96f82f7abfa7ecc0334e8fa16d3dc1cdc45b60b7af43fe4075d2357c0c1d60e98350f1afb1f2fe7a4d7cd2ad55b88e458e06b73c40b437331f5dab4"
  , sha512TestCase "How can you write a big system without C++?  -Paul Glick" "833f9248ab4a3b9e5131f745fda1ffd2dd435b30e965957e78291c7ab73605fd1912b0794e5c233ab0a12d205a39778d19b83515d6a47003f19cdee51d98c7e0" ]

-- | Tests our SHA-2 implementations against coreutils'.
testCoreutilsConformance = testGroup "conformance with coreutils"
  [ testProperty "SHA-224" $ testAgainstCoreutils sha224 "sha224sum"
  , testProperty "SHA-256" $ testAgainstCoreutils sha256 "sha256sum"
  , testProperty "SHA-384" $ testAgainstCoreutils sha384 "sha384sum"
  , testProperty "SHA-512" $ testAgainstCoreutils sha512 "sha512sum" ]

-- | Tests our SHA-2 implementations against openssl(1)'s.
testOpenSSLConformance = testGroup "conformance with OpenSSL"
  [ testProperty "SHA-224" $ testAgainstOpenSSL sha224 "sha224"
  , testProperty "SHA-256" $ testAgainstOpenSSL sha256 "sha256"
  , testProperty "SHA-384" $ testAgainstOpenSSL sha384 "sha384"
  , testProperty "SHA-512" $ testAgainstOpenSSL sha512 "sha512" ]
