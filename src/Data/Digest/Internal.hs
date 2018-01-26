{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE Rank2Types #-}

module Data.Digest.Internal where

import Control.Exception (assert)
import Data.Bits (Bits((.&.)), shiftR)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Unsafe as ByteString
import Data.Char (intToDigit)
import Data.Word (Word8)
import Foreign (Ptr, Storable, allocaArray, throwIf_, withForeignPtr)
import Foreign.C.Types
import Foreign.Marshal.Unsafe (unsafeLocalState)
import Unsafe.Coerce (unsafeCoerce)

import Cleanse (mallocCleansablePtr)

-- | A hash algorithm which follows the standard initialize-update-finalize
-- pattern.
data Algo = forall ctx. Storable ctx => Algo
  { mdLen :: CSize -- ^ The length of the digest.
  , mdInit :: Ptr ctx -> IO CInt -- ^ Initializes the context. Must return 1.
    -- | Adds the buffer to the context. Must not modify the buffer. Must return
    -- 1.
  , mdUpdate :: forall a. Ptr ctx -> Ptr a -> CSize -> IO CInt
    -- | Adds final padding to the context and writes the digest to the buffer.
  , mdFinal :: Ptr CUChar -> Ptr ctx -> IO CInt
  }

-- The type signatures in 'Algo' are suggestive of the functions exposed by the
-- BoringSSL API. Those functions fall into two broad categories--those which
-- always return 1 and those which return 1 only on success.

alwaysSucceeds :: IO CInt -> IO ()
alwaysSucceeds f = do
  r <- f
  assert (r == 1) (return ())

requireSuccess :: IO CInt -> IO ()
requireSuccess f = throwIf_ (/= 1) (const "BoringSSL failure") f

-- | The result of a hash operation.
newtype Digest =
  Digest ByteString
  deriving (Eq, Ord)

instance Show Digest where
  show (Digest d) = ByteString.foldr showHexPadded [] d
    where
      showHexPadded b xs =
        hexit (b `shiftR` 4 .&. 0x0f) : hexit (b .&. 0x0f) : xs
      hexit = intToDigit . fromIntegral :: Word8 -> Char

-- | Hashes according to the given 'Algo'.
hash :: Algo -> ByteString -> Digest
hash (Algo {mdLen, mdInit, mdUpdate, mdFinal}) bytes =
  let mdLen' = fromIntegral mdLen :: Int
  in unsafeLocalState $ do
     -- Allocate cleansable space for the hash context. This matches the
     -- behavior of the all-in-one hash functions in BoringSSL (@SHA256@,
     -- @SHA512@, etc.) which cleanse their buffers prior to returning.
     ctxFP <- mallocCleansablePtr
     withForeignPtr ctxFP $ \ctx -> do
       alwaysSucceeds $ mdInit ctx
       -- 'mdUpdate' treats its @buf@ argument as @const@, so the sharing
       -- inherent in 'ByteString.unsafeUseAsCStringLen' is fine.
       ByteString.unsafeUseAsCStringLen bytes $ \(buf, len) ->
         alwaysSucceeds $ mdUpdate ctx buf (fromIntegral len)
       d <-
         -- We could allocate another cleansable 'ForeignPtr' to store the
         -- digest, but we're going to be returning a copy of it as a ByteString
         -- anyway, so there's not really any point. Use 'allocaArray'; it's
         -- faster and simpler.
         allocaArray mdLen' $ \mdOut -> do
           requireSuccess $ mdFinal mdOut ctx
           -- 'mdOut' is a 'Ptr CUChar'. However, to make life more interesting,
           -- 'CString' is a 'Ptr CChar', and 'CChar' is signed. This is
           -- especially unfortunate given that all we really want to do is
           -- convert to a 'ByteString', which is unsigned. To work around it,
           -- we're going to cheat and let Haskell reinterpret-cast 'mdOut' to
           -- 'Ptr CChar' before it does its 'ByteString' ingestion.
           ByteString.packCStringLen (unsafeCoerce mdOut, mdLen')
       return (Digest d)
