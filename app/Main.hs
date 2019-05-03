{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE DeriveFoldable #-}
{-# LANGUAGE DeriveTraversable #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE StandaloneDeriving #-}
module Main where

import Lib
import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Codec.Serialise as CBOR
import qualified Codec.CBOR.Write as CBOR (toLazyByteString)
import qualified Codec.Serialise.Decoding as CBOR
import qualified Codec.Serialise.Encoding as CBOR
import qualified Codec.CBOR.Read as CBOR (deserialiseFromBytes)

main :: IO ()
main = do
    keypair <- generateKeyPair @Crypto @IO
    writeKeyPair keypair
    readKeyPair

skPath = "test_secret.key"
pkPath = "test_public.key"

writeKeyPair :: KeyPair Crypto -> IO ()
writeKeyPair (_pk, sk) =  do
    LBS.writeFile skPath $ serialisePrivateKey sk

readKeyPair :: IO ()
readKeyPair = do
    sk <- deserialisePrivateKey <$> readFileLbs skPath
    print sk
  where
    readFileLbs path = LBS.fromStrict <$> BS.readFile path
