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

module Internal.HKDF
  ( hkdfExtract, hkdfExpand
  ) where

import Foreign (Ptr)
import Foreign.C.Types

{#import Internal.Base#}
import Result

#include <openssl/hkdf.h>

hkdfExtract ::
  Ptr CUChar -> Ptr CULong
  -> Ptr EVPMD
  -> Ptr CUChar -> CULong
  -> Ptr CUChar -> CULong
  -> IO ()
hkdfExtract outKey outLen digest secret secretLen salt saltLen =
  requireSuccess $
    {#call HKDF_extract as ^#} outKey outLen digest secret secretLen salt saltLen

hkdfExpand ::
  Ptr CUChar -> CULong
  -> Ptr EVPMD
  -> Ptr CUChar -> CULong
  -> Ptr CUChar -> CULong
  -> IO ()
hkdfExpand outKey outLen digest prk prkLen info infoLen =
  requireSuccess $
    {#call HKDF_expand as ^#} outKey outLen digest prk prkLen info infoLen
