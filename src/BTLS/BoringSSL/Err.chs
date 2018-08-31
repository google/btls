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

{-# LANGUAGE CApiFFI #-}

module BTLS.BoringSSL.Err where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Foreign (Storable(peek), alloca, nullPtr)
import Foreign.C.String (CString, peekCString)
import Foreign.C.Types

#include <openssl/err.h>

-- Define a newtype for packed errors so c2hs doesn't try to marshal them.
newtype Err = Err {rawErrValue :: CUInt}
  deriving (Eq)

errGetLib :: Err -> ErrLib
errGetLib (Err e) = castEnum (errGetLib' e)

foreign import capi "openssl/err.h ERR_GET_LIB"
  errGetLib' :: CUInt -> CInt

errGetReason :: Err -> ErrR
errGetReason (Err e) = castEnum (errGetReason' e)

foreign import capi "openssl/err.h ERR_GET_REASON"
  errGetReason' :: CUInt -> CInt

errFlagString :: CInt
errFlagString = {#const ERR_FLAG_STRING#}

{#fun ERR_get_error_line_data as errGetErrorLineData
  { alloca- `FilePath' peekCStringPtr*
  , alloca- `Int' peekIntPtr*
  , alloca- `Maybe ByteString' peekErrorData*
  , alloca- `CInt' peek* }
  -> `Err' Err#}
  where
    peekCStringPtr p = do
      s <- peek p
      peekCString s
    peekIntPtr p = fmap fromIntegral (peek p)
    peekErrorData p = do
      s <- peek p
      if s == nullPtr
        then return Nothing
        else Just <$> ByteString.packCString s

{#fun ERR_error_string_n as errErrorStringN
  {rawErrValue `Err', id `CString', `Int'} -> `()'#}

{#fun ERR_clear_error as errClearError {} -> `()'#}

{#enum ERR_LIB_NONE as ErrLib
  { underscoreToCase
  , ERR_LIB_BN    as ErrLibBN
  , ERR_LIB_RSA   as ErrLibRSA
  , ERR_LIB_DH    as ErrLibDH
  , ERR_LIB_EVP   as ErrLibEvp
  , ERR_LIB_PEM   as ErrLibPEM
  , ERR_LIB_DSA   as ErrLibDSA
  , ERR_LIB_ASN1  as ErrLibASN1
  , ERR_LIB_EC    as ErrLibEC
  , ERR_LIB_SSL   as ErrLibSSL
  , ERR_LIB_BIO   as ErrLibBIO
  , ERR_LIB_PKCS7 as ErrLibPKCS7
  , ERR_LIB_PKCS8 as ErrLibPKCS8
  , ERR_LIB_OCSP  as ErrLibOCSP
  , ERR_LIB_UI    as ErrLibUI
  , ERR_LIB_ECDSA as ErrLibECDSA
  , ERR_LIB_ECDH  as ErrLibECDH
  , ERR_LIB_HMAC  as ErrLibHMAC
  , ERR_LIB_HKDF  as ErrLibHKDF }
  omit (ERR_NUM_LIBS)
  deriving (Eq)#}

{#enum define ErrR
  { ERR_R_SYS_LIB    as ErrRSysLib
  , ERR_R_BN_LIB     as ErrRBNLib
  , ERR_R_RSA_LIB    as ErrRRSALib
  , ERR_R_DH_LIB     as ErrRDHLib
  , ERR_R_EVP_LIB    as ErrREVPLib
  , ERR_R_BUF_LIB    as ErrRBufLib
  , ERR_R_OBJ_LIB    as ErrRObjLib
  , ERR_R_PEM_LIB    as ErrRPEMLib
  , ERR_R_DSA_LIB    as ErrRDSALib
  , ERR_R_X509_LIB   as ErrRX509Lib
  , ERR_R_ASN1_LIB   as ErrRASN1Lib
  , ERR_R_CONF_LIB   as ErrRConfLib
  , ERR_R_CRYPTO_LIB as ErrRCryptoLib
  , ERR_R_EC_LIB     as ErrRECLib
  , ERR_R_SSL_LIB    as ErrRSSLLib
  , ERR_R_BIO_LIB    as ErrRBIOLib
  , ERR_R_PKCS7_LIB  as ErrRPKCS7Lib
  , ERR_R_PKCS8_LIB  as ErrRPKCS8Lib
  , ERR_R_X509V3_LIB as ErrRX509v3Lib
  , ERR_R_RAND_LIB   as ErrRRandLib
  , ERR_R_ENGINE_LIB as ErrREngineLib
  , ERR_R_OCSP_LIB   as ErrROCSPLib
  , ERR_R_UI_LIB     as ErrRUILib
  , ERR_R_COMP_LIB   as ErrRCompLib
  , ERR_R_ECDSA_LIB  as ErrRECDSALib
  , ERR_R_ECDH_LIB   as ErrRECDHLib
  , ERR_R_HMAC_LIB   as ErrRHMACLib
  , ERR_R_USER_LIB   as ErrRUserLib
  , ERR_R_DIGEST_LIB as ErrRDigestLib
  , ERR_R_CIPHER_LIB as ErrRCipherLib
  , ERR_R_HKDF_LIB   as ErrRHKDFLib
  , ERR_R_FATAL                       as ErrRFatal
  , ERR_R_MALLOC_FAILURE              as ErrRMallocFailure
  , ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED as ErrRShouldNotHaveBeenCalled
  , ERR_R_PASSED_NULL_PARAMETER       as ErrRPassedNullParameter
  , ERR_R_INTERNAL_ERROR              as ErrRInternalError
  , ERR_R_OVERFLOW                    as ErrROverflow }
  deriving (Eq)#}

castEnum :: (Enum a, Enum b) => a -> b
castEnum = toEnum . fromEnum