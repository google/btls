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

module Data.Digest
  ( Algorithm
  , Digest
  , hash
  , md5
  , sha1
  , sha224
  , sha256
  , sha384
  , sha512
  ) where

import Foreign (Ptr)

{#import Data.Digest.Internal#}

#include <openssl/digest.h>

md5 :: Algorithm
md5 = Algorithm {#call pure EVP_md5 as ^#}

sha1 :: Algorithm
sha1 = Algorithm {#call pure EVP_sha1 as ^#}

sha224 :: Algorithm
sha224 = Algorithm {#call pure EVP_sha224 as ^#}

sha256 :: Algorithm
sha256 = Algorithm {#call pure EVP_sha256 as ^#}

sha384 :: Algorithm
sha384 = Algorithm {#call pure EVP_sha384 as ^#}

sha512 :: Algorithm
sha512 = Algorithm {#call pure EVP_sha512 as ^#}
