// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

#include <openssl/cipher.h>
#include <openssl/digest.h>

void btlsFinalizeEVPCipherCtx(EVP_CIPHER_CTX* const ctx) {
  (void)EVP_CIPHER_CTX_cleanup(ctx);
}

void btlsFinalizeEVPMDCtx(EVP_MD_CTX* const ctx) {
  (void)EVP_MD_CTX_cleanup(ctx);
}
