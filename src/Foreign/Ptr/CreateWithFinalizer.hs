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

module Foreign.Ptr.CreateWithFinalizer (createWithFinalizer) where

import Foreign
  (FinalizerPtr, ForeignPtr, Ptr, Storable, addForeignPtrFinalizer,
   mallocForeignPtr, withForeignPtr)

createWithFinalizer ::
  Storable a => (Ptr a -> IO ()) -> FinalizerPtr a -> IO (ForeignPtr a)
createWithFinalizer initialize finalize = do
  fp <- mallocForeignPtr
  withForeignPtr fp initialize
  addForeignPtrFinalizer finalize fp
  return fp
