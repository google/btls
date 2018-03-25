{-# LANGUAGE ScopedTypeVariables #-}

module Foreign.Ptr.ConstantTimeEquals where

import Foreign (Ptr)
import Foreign.C.Types

foreign import ccall "openssl/mem.h CRYPTO_memcmp"
  cryptoMemcmp :: Ptr a -> Ptr a -> CSize -> IO CInt

-- | Directly compares two buffers for equality. This operation takes an amount
-- of time dependent on the specified size but independent of either buffer's
-- contents.
constantTimeEquals :: Ptr a -> Ptr a -> Int -> IO Bool
constantTimeEquals a b size =
  let size' = fromIntegral size :: CSize
  in (== 0) <$> cryptoMemcmp a b size'
