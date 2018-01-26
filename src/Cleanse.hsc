{-# LANGUAGE ScopedTypeVariables #-}

-- | This module wraps BoringSSL's @OPENSSL_cleanse@, which securely overwrites
-- memory. ("Securely" here means that BoringSSL uses some assembly magic to
-- prevent the compiler from optimizing out the write.) However, the module
-- doesn't actually expose @OPENSSL_cleanse@ directly; instead, it lets you
-- allocate 'ForeignPtr's with cleansing registered as a finalizer. GHC runs all
-- 'ForeignPtr' finalizers prior to program termination, which gives the
-- 'ForeignPtr's allocated this way the approximately same security guarantees
-- as memory allocated through BoringSSL's allocator interface. In particular,
-- unless you exit your program through GHC's foreign function interface, all
-- memory allocated through 'mallocCleansablePtr' will be forcibly cleared prior
-- to program exit.
module Cleanse
  ( mallocCleansablePtr
  ) where

import Foreign
       (FinalizerPtr, ForeignPtr, Storable(poke, sizeOf),
        addForeignPtrFinalizer, mallocForeignPtrBytes, withForeignPtr)
import Foreign.C.Types
import Foreign.ForeignPtr.Compat (plusForeignPtr)

#include <stddef.h>

#include <openssl/mem.h>

-- We implement 'mallocCleansablePtr' using the standard allocator technique of
-- saving the allocated region size immediately before the allocated region.

#def struct __attribute__((__packed__)) Buffer {
  size_t size;
  char data[];
};

bufferSize :: Int
bufferSize = #size struct Buffer

dataOffset :: Int
dataOffset = #offset struct Buffer, data

mallocCleansablePtr :: forall a. Storable a => IO (ForeignPtr a)
mallocCleansablePtr = do
  -- Allocate the buffer.
  let dataSize = sizeOf (undefined :: a)
  fp <- mallocForeignPtrBytes (bufferSize + dataSize)
  -- Save the data size.
  withForeignPtr fp $ \p -> poke p (fromIntegral dataSize :: CSize)
  -- Now that the size is saved, we can register the cleansing finalizer. This
  -- will look at the size and wipe the buffer.
  addForeignPtrFinalizer btlsCleansePtr fp
  -- Return a pointer to the data region.
  return (fp `plusForeignPtr` dataOffset :: ForeignPtr a)

-- The cleansing finalizer itself is totally straightforward.

#def void btlsCleanse(struct Buffer* const p) {
  OPENSSL_cleanse(p->data, p->size);
}

foreign import ccall "&btlsCleanse"
  btlsCleansePtr :: FinalizerPtr a
