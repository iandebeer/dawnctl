package  xyz.didx

import cats.effect.IO
import xyz.didx.DawnCtl.ContextEntries
import os.*
import cats.effect.IO
import DawnCtl.*
import io.circe.parser.*
import io.circe.syntax.*
import io.circe.generic.auto.*
import io.circe.Json

object ContextFileOps :
  // Read Context Entries from a file if exist else create Context Entry file
  def readContextEntries(contextEntriesFile:Path): IO[ContextEntries] = IO.pure {
        if (os.exists(contextEntriesFile)) 
            val contextEntriesJson = os.read(contextEntriesFile)
            val contextEntries = decode[Json](contextEntriesJson).getOrElse(Json.obj()).as[Map[String,DawnCtl.ContextEntry]].getOrElse(Map.empty)
            ContextEntries(contextEntries)
        else 
            val contextEntries = Json.obj()
            os.write(contextEntriesFile, contextEntries.toString(),createFolders = true)
            ContextEntries(contextEntries.as[Map[String, DawnCtl.ContextEntry]].getOrElse(Map.empty))
    }
  // Update Context Entries by adding a ContextEntry to the map in a file
    def updateContextEntries(contextEntriesFile:Path, name:String, contextEntry: ContextEntry): IO[ContextEntries] = 
        for 
            cef <- readContextEntries(contextEntriesFile)
            updatedContextEntries = cef.copy(entries = cef.entries + (name -> contextEntry))
            _ <- IO.pure(os.write(contextEntriesFile, updatedContextEntries.asJson.toString()))
        yield updatedContextEntries

    def deleteContextEntries(contextEntriesFile:Path, name:String): IO[ContextEntries] =
        for 
            cef <- readContextEntries(contextEntriesFile)
            updatedContextEntries = cef.copy(entries = cef.entries - name)
            _ <- IO.pure(os.write(contextEntriesFile, updatedContextEntries.asJson.toString()))
        yield updatedContextEntries

  // Store public key for a context entry in a file
    def storePublicKey(contextEntriesFile:Path, name:String, publicKey: String): IO[ContextEntries] = 
        for 
            cef <- readContextEntries(contextEntriesFile)
            updatedContextEntries = cef.copy(entries = cef.entries + (name -> ContextEntry(did = "", publicKey = Some(publicKey))))
            _ <- IO.pure(os.write.over(contextEntriesFile, updatedContextEntries.asJson.toString(),createFolders = true))
        yield updatedContextEntries
        
   // Get public key for a context entry from a file
    def getPublicKey(contextEntriesFile:Path, name:String): IO[Option[String]] = 
        for 
            cef <- readContextEntries(contextEntriesFile)
        yield cef.entries.get(name).flatMap(_.publicKey)    
 // get did for a context entry from a file
   
            