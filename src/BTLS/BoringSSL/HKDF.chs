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

module BTLS.BoringSSL.HKDF
  ( hkdfExtract, hkdfExpand
  ) where

import Data.ByteString (ByteString)
import Foreign (Ptr)
import Foreign.C.Types

{#import BTLS.BoringSSL.Base#}
import BTLS.Buffer (unsafeUseAsCBuffer)
import BTLS.Result

#include <openssl/hkdf.h>

{#fun HKDF_extract as hkdfExtract
  { id `Ptr CUChar', id `Ptr CULong', `Ptr EVPMD'
  , unsafeUseAsCBuffer* `ByteString'&, unsafeUseAsCBuffer* `ByteString'& }
  -> `()' requireSuccess*-#}

{#fun HKDF_expand as hkdfExpand
  { id `Ptr CUChar', id `CULong', `Ptr EVPMD', unsafeUseAsCBuffer* `ByteString'&
  , unsafeUseAsCBuffer* `ByteString'& } -> `()' requireSuccess*-#}
