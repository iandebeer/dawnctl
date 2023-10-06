package xyz.didx

import cats.effect.IO
import os.*
import cats.effect.IO
import DawnCtl.*
import io.circe.parser.*
import io.circe.syntax.*
import io.circe.generic.auto.*
import io.circe.Json
import java.security.interfaces.ECPublicKey
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.ECKey
import DIDOps.*
import Crypto.*
import cats.data.EitherT
import java.security.PublicKey

object ContextFileOps:

  def getContextEntries(name: String): IO[Either[Error, ContextEntries]] =
    for
      contextEntries <- readContextEntries(contextFilePath)
    yield contextEntries

  def addNewContext(name: String, cf: ContextEntries, channel: ChannelType): IO[Either[Error, ContextEntry]] =
    (for
      keyStore    <- EitherT(getKeyStore("password", keyStorePath))
      keyPair     <- EitherT(createKeyPairRSA())
      certificate <- EitherT(createSelfSignedCertificate(name))
      _           <- EitherT(storeCertificate(keyStore, certificate, name, "password".toArray[Char]))
      kp          <- EitherT(createKeyPair(name))
      _           <- EitherT(storePrivateKey(keyStore, kp, name, "password", certificate))

      // check if the context name already exists and return the did or generate a new did
      pubKey <- EitherT.rightT(kp.toECPublicKey())
      ks      = new JWKSet(kp).toPublicJWKSet().toString()
      kSet    =
        parse(ks).getOrElse(Json.obj()).as[KeyPairs].getOrElse(KeyPairs(List.empty)).keys.headOption.getOrElse(KeyPair(
          "",
          "",
          "",
          "",
          ""
        ))
      didKey <- EitherT.fromOption(makeDidKey(pubKey, kSet.kty, kSet.crv), Error("Invalid Public Key"))
      root   <- EitherT(createDWN(dwnUrl, didKey))
      did     = root.tenant.tenantId.dwnDidEquivalent

      contextEntry <- EitherT.rightT(ContextEntry(
                        did,
                        Some(didKey),
                        Some(keyStorePath.toString()),
                        Some(encodeToBase58(pubKey.getEncoded())),
                        Some(kSet),
                        Some(channel.toString())
                      ))
      _            <- EitherT(updateContextEntries(contextFilePath, name, contextEntry))

    // did          <- EitherT.fromOption(pubKey,generateDid(name))
    /*  match
                        case Some(pk) => IO((s"did:key:$pk", ""))
                        case _   => generateDid(name) */
    // case Some(pk) => IO((s"did:key:$pk", ""))
    // case None     => generateDid(name)
    // _            <- IO.println(s"Generated DID: ${did._1}")
    // keypair      <- did._2 match
    //                   case "" => IO(None)
    //                   case _  => IO(
    //                       parse(did._2).getOrElse(Json.obj()).as[KeyPairs].getOrElse(KeyPairs(List.empty)).keys.headOption
    //                    )
    // contextEntry <-
    // IO(ContextEntry(did._1, Some(keyStorePath.toString()), keypair.map(_.x), keypair))
    yield contextEntry).value

  // did from pubkey

  // Read Context Entries from a file if exist else create Context Entry file
  def readContextEntries(contextEntriesFile: Path): IO[Either[Error, ContextEntries]] = IO {
    // Check if the file exists
    val entries = if (os.exists(contextEntriesFile))
      // Read the current entries from the file
      val contextEntriesJson = os.read(contextEntriesFile)
      // Parse the JSON
      parse(contextEntriesJson).getOrElse(Json.obj()).as[ContextEntries].getOrElse(ContextEntries(Map.empty))
    // ContextEntries(contextEntries)
    else
      // Create an empty object
      val contextEntries = Json.obj()
      // Write the empty object to the file
      os.write(contextEntriesFile, contextEntries.toString(), createFolders = true)
      // Return an empty ContextEntries instance
      ContextEntries(contextEntries.as[Map[String, ContextEntry]].getOrElse(Map.empty))
    Right(entries)
  }
  // Update Context Entries by adding a ContextEntry to the map in a file
  def updateContextEntries(
    contextEntriesFile: Path,
    name: String,
    contextEntry: ContextEntry
  ): IO[Either[Error, ContextEntries]] =
    (for
      cef                   <- EitherT(readContextEntries(contextEntriesFile))
      updatedContextEntries <- EitherT.rightT(cef.copy(entries = cef.entries + (name -> contextEntry)))
      _                     <- EitherT.rightT(os.write.over(contextEntriesFile, updatedContextEntries.asJson.toString()))
    yield updatedContextEntries).value

  def deleteContextEntries(name: String): IO[Either[Error, ContextEntries]] =
    (for
      cef                   <- EitherT(readContextEntries(contextFilePath))
      updatedContextEntries <- EitherT.rightT(cef.copy(entries = cef.entries - name))
      _                     <- EitherT.rightT(os.write(contextFilePath, updatedContextEntries.asJson.spaces2))
    yield updatedContextEntries).value

  // Store public key for a context entry in a file
  def storePublicKey(
    contextEntriesFile: Path,
    name: String,
    publicKey: String
  ): IO[Either[Error, ContextEntries]] =
    (for
      cef                   <- EitherT(readContextEntries(contextEntriesFile))
      updatedContextEntries <- EitherT.rightT(cef.copy(entries =
                                 cef.entries + (name -> ContextEntry(did = "", None, None))
                               ))
      _                     <- EitherT.rightT(os.write.over(
                                 contextEntriesFile,
                                 updatedContextEntries.asJson.toString(),
                                 createFolders = true
                               ))
    yield updatedContextEntries).value

  // Get public key for a context entry from a file
  def getPublicKey(contextEntriesFile: Path, name: String): IO[Either[Error, Option[ECPublicKey]]] =
    (for
      cef      <- EitherT(readContextEntries(contextEntriesFile))
      keyPairs <- EitherT.rightT(cef.entries.get(name).flatMap(_.keypair).map(kp => KeyPairs(List(kp))))
      // _ <- IO.println(s"key pairs ${keyPairs.getOrElse(KeyPairs(List.empty))}")
      pubKey   <- EitherT.rightT(keyPairs.map(kp =>
                    val json = kp.asJson.spaces2
                    //  println(s"json: $json")
                    val ks   = JWKSet.parse(json)
                    ks.toPublicJWKSet().getKeys.get(0).asInstanceOf[ECKey].toECPublicKey
                  ))
    //  ks.getKeys.get(0).asInstanceOf[ECKey].toECPublicKey))
    // b64key <- IO(cef.entries.get(name).flatMap(_.keyPair).map(_.publicKey))
    yield pubKey).value
// get did for a context entry from a file
