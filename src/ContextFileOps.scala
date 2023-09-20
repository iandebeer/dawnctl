package xyz.didx

import cats.effect.IO
import xyz.didx.DawnCtl.ContextEntries
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

object ContextFileOps:
  // Read Context Entries from a file if exist else create Context Entry file
  def readContextEntries(contextEntriesFile: Path): IO[ContextEntries] = IO.pure {
    if (os.exists(contextEntriesFile))
      val contextEntriesJson = os.read(contextEntriesFile)
      parse(contextEntriesJson).getOrElse(Json.obj()).as[ContextEntries].getOrElse(ContextEntries(Map.empty))
    // ContextEntries(contextEntries)
    else
      val contextEntries = Json.obj()
      os.write(contextEntriesFile, contextEntries.toString(), createFolders = true)
      ContextEntries(contextEntries.as[Map[String, DawnCtl.ContextEntry]].getOrElse(Map.empty))
  }
  // Update Context Entries by adding a ContextEntry to the map in a file
  def updateContextEntries(
    contextEntriesFile: Path,
    name: String,
    contextEntry: ContextEntry
  ): IO[ContextEntries] =
    for
      cef                  <- readContextEntries(contextEntriesFile)
      updatedContextEntries = cef.copy(entries = cef.entries + (name -> contextEntry))
      _                    <- IO.pure(os.write(contextEntriesFile, updatedContextEntries.asJson.toString()))
    yield updatedContextEntries

  def deleteContextEntries(contextEntriesFile: Path, name: String): IO[ContextEntries] =
    for
      cef                  <- readContextEntries(contextEntriesFile)
      updatedContextEntries = cef.copy(entries = cef.entries - name)
      _                    <- IO.pure(os.write(contextEntriesFile, updatedContextEntries.asJson.toString()))
    yield updatedContextEntries

  // Store public key for a context entry in a file
  def storePublicKey(
    contextEntriesFile: Path,
    name: String,
    publicKey: String
  ): IO[ContextEntries] =
    for
      cef                  <- readContextEntries(contextEntriesFile)
      updatedContextEntries = cef.copy(entries =
                                cef.entries + (name -> ContextEntry(did = "", None, None))
                              )
      _                    <- IO.pure(os.write.over(
                                contextEntriesFile,
                                updatedContextEntries.asJson.toString(),
                                createFolders = true
                              ))
    yield updatedContextEntries

  // Get public key for a context entry from a file
  def getPublicKey(contextEntriesFile: Path, name: String): IO[Option[ECPublicKey]] =
    for
      cef <- readContextEntries(contextEntriesFile)
      keyPairs <- IO.pure(cef.entries.get(name).flatMap(_.keypair).map(kp => KeyPairs(List(kp))))
      //_ <- IO.println(s"key pairs ${keyPairs.getOrElse(KeyPairs(List.empty))}")
      pubKey <- IO.pure(keyPairs.map(kp => 
        val json  = kp.asJson.spaces2
        println(s"json: $json")
        val ks = JWKSet.parse(json)
        ks.toPublicJWKSet().getKeys.get(0).asInstanceOf[ECKey].toECPublicKey))
      //  ks.getKeys.get(0).asInstanceOf[ECKey].toECPublicKey))
      // b64key <- IO.pure(cef.entries.get(name).flatMap(_.keyPair).map(_.publicKey))
    yield pubKey
// get did for a context entry from a file
