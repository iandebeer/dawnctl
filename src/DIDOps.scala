package xyz.didx

import cats.effect.*
import cats.syntax.all.*
import Crypto.*
import ContextFileOps.*
import com.nimbusds.jose.jwk.JWKSet

object DIDOps:
  def generateDid(alias: String): IO[(String, String)] =
    for
      keyStore    <- getKeyStore("password", keyStorePath)
      keyPair     <- createKeyPairRSA()
      certificate <- createSelfSignedCertificate(alias)
      _           <- storeCertificate(keyStore, certificate, alias, "password".toArray[Char])

      kp <- createKeyPair(alias, keyStorePath)
      _  <- storePrivateKey(keyStorePath, keyStore, kp, alias, "password", certificate)
    // _  <- storePublicKey(contextFilePath, alias, kp.getPublic().toString())
    yield (s"did:key:${kp.computeThumbprint().toString()}", new JWKSet(kp).toPublicJWKSet().toString())

  def fetchDID(alias: String): IO[Either[Throwable, String]] =
    for

      keyStore <- getKeyStore("password", keyStorePath)
      pk       <- getPublicKey(contextFilePath, alias)

    /*   getPublicKey(contextFilePath, alias).unsafeRunSync() match
        case Some(pk) => s"did:key:$pk".asRight[Throwable].pure[IO]
        case None     => Left(new Exception("Invalid Public Key")).pure[IO] */
    yield s"did:key:$pk".asRight[Throwable]
