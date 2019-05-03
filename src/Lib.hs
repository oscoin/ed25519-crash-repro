{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE DeriveFoldable #-}
{-# LANGUAGE DeriveTraversable #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE StandaloneDeriving #-}

module Lib where

import qualified Crypto.PubKey.Ed25519 as Ed25519
import           Crypto.Random.Types (MonadRandom)
import           Data.ByteArray (ByteArrayAccess, convert)
import           Data.Bifunctor (second)
import           Control.Applicative (liftA2)
import           Crypto.Error (eitherCryptoError)
import           Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as LBS
import Codec.Serialise as CBOR
import qualified Codec.CBOR.Write as CBOR (toLazyByteString)
import qualified Codec.Serialise.Decoding as CBOR
import qualified Codec.Serialise.Encoding as CBOR
import qualified Codec.CBOR.Read as CBOR (deserialiseFromBytes)

data Crypto

type KeyPair c = (PublicKey c, PrivateKey c)

data Signed c msg = Signed
    { sigMessage   :: msg
    , sigSignature :: Signature c
    } deriving (Functor, Foldable, Traversable)

deriving instance (Show (Signature c), Show msg) => Show (Signed c msg)
deriving instance (Eq (Signature c), Eq msg) => Eq (Signed c msg)
deriving instance (Ord (Signature c), Ord msg) => Ord (Signed c msg)

class (Eq (Signature c), Eq (PublicKey c)) => HasDigitalSignature c where
    data family PublicKey c :: *
    data family PrivateKey c :: *
    data family Signature c :: *

    sign   :: (ByteArrayAccess msg, MonadRandom m) => PrivateKey c -> msg -> m (Signed c msg)
    verify :: ByteArrayAccess msg => PublicKey c -> Signed c msg -> Bool

    -- | Generate a new random keypair.
    generateKeyPair :: MonadRandom m => m (KeyPair c)

data PK c k = PK k

deriving instance (Show k) => Show (PK c k)

newtype SK k = SK k deriving Show

-- Instances

instance HasDigitalSignature Crypto where

    newtype PublicKey Crypto =
        PublicKey (PK Crypto Ed25519.PublicKey) deriving (Show, Eq)

    newtype PrivateKey Crypto = PrivateKey (SK Ed25519.SecretKey) deriving Show

    newtype Signature Crypto =
        Signature Ed25519.Signature deriving Show

    sign (PrivateKey (SK sk)) bytes =
        pure $ Signed bytes . Signature . Ed25519.sign sk (Ed25519.toPublic sk) $ bytes

    verify (PublicKey (PK pk)) (Signed bytes (Signature sig)) =
        Ed25519.verify pk bytes sig

    generateKeyPair = do
        sk <- Ed25519.generateSecretKey
        let pk = Ed25519.toPublic sk
        pure (PublicKey $ PK pk, PrivateKey $ SK sk)

instance Eq (Signature Crypto) where
    (Signature s1) == (Signature s2) = s1 == s2

{------------------------------------------------------------------------------
  Various instances
-------------------------------------------------------------------------------}

instance Eq (PK Crypto Ed25519.PublicKey) where
    (PK a1) == (PK a2) = a1 == a2

{------------------------------------------------------------------------------
  Utility functions
-------------------------------------------------------------------------------}

serialisePrivateKey :: PrivateKey Crypto -> LBS.ByteString
serialisePrivateKey (PrivateKey (SK sk)) =
    CBOR.toLazyByteString $
       CBOR.encodeListLen 2
    <> CBOR.encodeWord 0
    <> CBOR.encodeBytes (convert sk)

deserialisePrivateKey
    :: LBS.ByteString
    -> Either CBOR.DeserialiseFailure (PrivateKey Crypto)
deserialisePrivateKey bs = second snd $ CBOR.deserialiseFromBytes decoder bs
  where
    decoder = do
        pre <- liftA2 (,) CBOR.decodeListLen CBOR.decodeWord
        case pre of
            (2, 0) -> do
                skE <- Ed25519.secretKey <$> CBOR.decodeBytes
                case eitherCryptoError skE of
                  Left e -> fail ("CBOR SecretKey conversion failed: " ++ show e)
                  Right sk -> pure . PrivateKey $ SK sk
            _ -> fail "CBOR: Invalid SK"
