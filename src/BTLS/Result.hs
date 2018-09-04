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

module BTLS.Result
  ( alwaysSucceeds, requireSuccess
  , Result, Error, file, line, errorData, errorDataIsHumanReadable
  , check
  ) where

import Control.Concurrent (rtsSupportsBoundThreads, runInBoundThread)
import Control.Exception (assert)
import Control.Monad (guard, unless, when)
import Control.Monad.Loops (unfoldM)
import Control.Monad.Trans.Except (ExceptT(ExceptT))
import Data.Bits ((.&.))
import Data.ByteString (ByteString)
import Foreign (allocaArray)
import Foreign.C.String (peekCString)
import Foreign.C.Types
import Foreign.Marshal.Unsafe (unsafeLocalState)

import BTLS.BoringSSL.Err

alwaysSucceeds :: CInt -> IO ()
alwaysSucceeds r = assert (r == 1) (return ())

requireSuccess :: CInt -> IO ()
requireSuccess r = when (r /= 1) $ ioError (userError "BoringSSL failure")

type Result = Either [Error]

-- | An error which occurred during processing.
data Error = Error
  { err :: Err
  , file :: FilePath
  , line :: Int
  , errorData :: Maybe ByteString
  , flags :: CInt
  } deriving Eq

errorDataIsHumanReadable :: Error -> Bool
errorDataIsHumanReadable e = flags e .&. errFlagString == 1

instance Show Error where
  show e =
    let len = 120 in
    unsafeLocalState $
      allocaArray len $ \pOut -> do
        errErrorStringN (err e) pOut len
        peekCString pOut

errorFromTuple :: (Err, FilePath, Int, Maybe ByteString, CInt) -> Error
errorFromTuple = uncurry5 Error

dequeueError :: IO (Maybe Error)
dequeueError = do
  e@((Err code), _file, _line, _extra, _flags) <- errGetErrorLineData
  guard (code /= 0)
  return (Just (errorFromTuple e))

check :: IO Int -> ExceptT [Error] IO ()
check f = do
  unless rtsSupportsBoundThreads $
    error "btls requires the threaded runtime. Please recompile with -threaded."
  ExceptT $ runInBoundThread $ do
    -- TODO(bbaren): Assert that the error queue is clear
    r <- f
    if r == 1
      then Right <$> return ()
      else Left <$> unfoldM dequeueError

uncurry5 :: (a -> b -> c -> d -> e -> z) -> (a, b, c, d, e) -> z
uncurry5 f (a, b, c, d, e) = f a b c d e
