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

module Codec.Crypto.Encryption
  ( Cipher, blockSize
  , rc4
  , doCipher, lazyCipher, CipherParams(..)
  , CipherDirection(Encrypt, Decrypt)

    -- * Error handling
  , Error
  ) where

import Control.Monad.Trans.Except (ExceptT, runExceptT)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as Lazy (ByteString)
import qualified Data.ByteString.Lazy as ByteString.Lazy
import Foreign (ForeignPtr, Ptr, nullPtr)
import Foreign.C.Types
import Foreign.Marshal.Unsafe (unsafeLocalState)
import System.IO.Unsafe (unsafeInterleaveIO)

import BTLS.BoringSSL.Base (EVPCipher, EVPCipherCtx, noEngine)
import BTLS.BoringSSL.Cipher
import BTLS.BoringSSL.Obj (objNID2SN)
import BTLS.Buffer (onBufferOfMaxSize', unsafeUseAsCBuffer)
import BTLS.Result (Error, check)

-- | A cipher.
newtype Cipher = Cipher (Ptr EVPCipher)

instance Eq Cipher where
  Cipher a == Cipher b = evpCipherNID a == evpCipherNID b

instance Show Cipher where
  show (Cipher c) = maybe "<cipher>" id (objNID2SN (evpCipherNID c))

blockSize :: Cipher -> Int
blockSize (Cipher c) = evpCipherBlockSize c

rc4 :: Cipher
rc4 = Cipher evpRC4

data CipherParams = CipherParams
  { cipher :: Cipher
  , secretKey :: ByteString
  , iv :: ByteString
  , direction :: CipherDirection
  } deriving (Eq, Show)

-- | Performs an encryption or decryption operation.
doCipher :: CipherParams -> Lazy.ByteString -> Either [Error] ByteString
doCipher params plaintext = mconcat <$> sequence (lazyCipher params plaintext)

lazyCipher :: CipherParams -> Lazy.ByteString -> [Either [Error] ByteString]
lazyCipher params plaintext =
  unsafeLocalState $ do
    ctx <- mallocEVPCipherCtx
    -- TODO(bbaren): Do 'key params' and 'iv params' need to remain live past
    -- initialization? If not, we could move these 'unsafeUseAsCBuffer's into
    -- 'initializeCipherCtx'.
    unsafeUseAsCBuffer (secretKey params) $ \(pKey, keyLen) ->
      unsafeUseAsCBuffer (iv params) $ \(pIV, _ivLen) -> do
        -- TODO(bbaren): Validate key and IV length.
        initializeResult <- runExceptT $
          initializeCipherCtx ctx params (pKey, keyLen) pIV
        case initializeResult of
          Left e -> return [Left e]
          Right () ->
            cipherChunks ctx (cipher params) (ByteString.Lazy.toChunks plaintext)

-- | Initializes a cipher context and sets the key length.
initializeCipherCtx ::
     ForeignPtr EVPCipherCtx
  -> CipherParams
  -> (Ptr CUChar, Int)
  -> Ptr CUChar
  -> ExceptT [Error] IO ()
initializeCipherCtx ctx params (pKey, keyLen) pIV = do
  let Cipher pCipher = cipher params
      engine = noEngine
  -- This function deals with a catch-22: We can't call
  -- 'evpCipherCtxSetKeyLength' on an uninitialized 'EVPCipherCtx', but
  -- 'evpCipherInitEx' requires a key of @keyLength cipher@ in length.
  -- Fortunately, @EVP_CipherInit_ex@'s documentation says that "If ctx has been
  -- previously configured with a cipher then cipher, key and iv may be NULL
  -- [...] to reuse the previous values." So first, we call 'evpCipherInitEx'
  -- with a dummy key (@NULL@); then, we set the key length; and finally, we
  -- reload 'ctx' with the actual key.
  check $ evpCipherInitEx ctx pCipher engine dummyKey pIV (direction params)
  check $ evpCipherCtxSetKeyLength ctx keyLen
  check $ evpCipherInitEx ctx reuseCipher engine pKey reuseIV ReuseDirection
  where dummyKey = nullPtr
        reuseCipher = nullPtr
        reuseIV = nullPtr

-- | Lazily performs a cipher operation on 'chunks'. The operation will stop
-- when all chunks have been ciphered or at the first error.
cipherChunks ::
     ForeignPtr EVPCipherCtx
  -> Cipher
  -> [ByteString]
  -> IO [Either [Error] ByteString]
cipherChunks ctx cipher = loop
  where loop (x:xs) = do
          y <- cipherChunk ctx cipher x
          case y of
            e@(Left _) -> return [e] -- Encrypting the chunk failed, so give up.
            Right _ -> do
              ys <- unsafeInterleaveIO (loop xs) -- Lazily keep encrypting.
              return (y : ys)
        loop [] = do
          -- Grab any remaining data.
          y <- onBufferOfMaxSize' (blockSize cipher) $ \pOut pOutLen ->
            check $ evpCipherFinalEx ctx pOut pOutLen
          return [y]

cipherChunk ::
     ForeignPtr EVPCipherCtx
  -> Cipher
  -> ByteString
  -> IO (Either [Error] ByteString)
cipherChunk ctx (Cipher pCipher) chunk = do
  let maxCiphertextLen = ByteString.length chunk + evpCipherBlockSize pCipher
  onBufferOfMaxSize' maxCiphertextLen $ \pOut pOutLen ->
    check $ evpCipherUpdate ctx pOut pOutLen chunk
