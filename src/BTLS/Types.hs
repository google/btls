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

module BTLS.Types where

import Foreign (Ptr)

import BTLS.BoringSSL.Base (EVPMD)
import BTLS.BoringSSL.Digest (evpMDType)
import BTLS.BoringSSL.Obj (objNID2SN)

-- | A cryptographic hash function.
newtype Algorithm = Algorithm (Ptr EVPMD)

instance Eq Algorithm where
  Algorithm a == Algorithm b = evpMDType a == evpMDType b

instance Show Algorithm where
  show (Algorithm md) = maybe "<algorithm>" id (objNID2SN (evpMDType md))
