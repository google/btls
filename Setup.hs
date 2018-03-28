-- Copyright 2017 Google LLC
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

module Main
  ( main
  ) where

import qualified Distribution.PackageDescription
       as PackageDescription
import qualified Distribution.Simple as Simple
import qualified Distribution.Simple.LocalBuildInfo
       as LocalBuildInfo
import qualified Distribution.Simple.Setup as Setup
import qualified Distribution.Simple.Utils as Utils
import System.Directory (getCurrentDirectory)
import System.FilePath ((</>))

main =
  let h = Simple.simpleUserHooks
  in Simple.defaultMainWithHooks
       h
       { Simple.preConf =
           \args flags
             -- Cabal expects to find BoringSSL's libraries already built at the
             -- time of configuration, so we must build BoringSSL completely
             -- here.
            -> do
             boringsslBuild flags
             Simple.preConf h args flags
       , Simple.confHook =
           \info flags -> do
             buildinfo <- Simple.confHook h info flags
             boringsslUpdateExtraLibDirs buildinfo
       }

boringsslDir = "third_party" </> "boringssl"

boringsslLibDir = boringsslDir </> "lib"

boringsslBuild flags
  -- Build BoringSSL.
 = do
  let buildDir = boringsslDir </> "build"
  mkdir buildDir
  cmd
    [ "cmake"
    , "-GNinja"
    , "-DCMAKE_BUILD_TYPE=Release"
    , "-B" ++ buildDir
    , "-H" ++ boringsslDir </> "src"
    ]
  cmd ["ninja", "-C", buildDir]
  -- Rename BoringSSL's libraries so we don't accidentally grab OpenSSL.
  mkdir boringsslLibDir
  Utils.installOrdinaryFile
    v
    (buildDir </> "crypto" </> "libcrypto.a")
    (boringsslLibDir </> "libbtls_crypto.a")
  where
    v = Setup.fromFlag (Setup.configVerbosity flags)
    mkdir = Utils.createDirectoryIfMissingVerbose v True
    cmd (bin:args) = Utils.rawSystemExit v bin args

boringsslUpdateExtraLibDirs buildinfo = do
  let pkg = LocalBuildInfo.localPkgDescr buildinfo
      Just lib = PackageDescription.library pkg
      libBuild = PackageDescription.libBuildInfo lib
      dirs = PackageDescription.extraLibDirs libBuild
  root <- getCurrentDirectory
  return
    buildinfo
    { LocalBuildInfo.localPkgDescr =
        pkg
        { PackageDescription.library =
            Just $
            lib
            { PackageDescription.libBuildInfo =
                libBuild
                { PackageDescription.extraLibDirs =
                    (root </> boringsslLibDir) : dirs
                }
            }
        }
    }
