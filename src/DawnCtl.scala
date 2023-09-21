package xyz.didx

import cats.effect.*
import cats.syntax.all.*
import com.monovore.decline.*
import com.monovore.decline.effect.*
import io.circe.*
import io.circe.parser.*
import io.circe.syntax.*
import io.circe.Encoder.encodeUnit
import io.circe.generic.semiauto.*
import io.circe.Encoder.encodeJsonObject

import os.*

import fs2.*
import scala.util.Try
import fs2.concurrent.Channel
import java.net.URI
import org.http4s.CacheDirective.public
import java.security.interfaces.RSAPublicKey
import cats.effect.unsafe.implicits.global
import java.util.Base64
import java.security.PublicKey
import ContextFileOps.*
import Crypto.*
import DIDOps.*

import org.typelevel.vault.Key
import com.nimbusds.jose.jwk.JWKSet

object DawnCtl extends CommandIOApp("dawnctl", "A command-line interface to your DWN Context"):

  val helpInformation: String = """
  |Usage: dawnctl [command] [options]
  |Command: init [optional-arg]
  |Initialize your DWN Context. A DID generated by the DWN Network will be stored in the Context file <$user.home/.dawn/dawn.conf>
  |Command: delete
  |Delete something
  |Command: get [optional-arg]
  |Get something
  |Command: relay
  |Relay something
  |Options:
  |  --help
  |    This help information
  """

  val initCommand: Command[IO[Unit]] = Command(
    "init",
    "Initialize your DWN Context. A DID generated by the DWN Network will be stored in the Context file <$user.home/.dawn/dawn.conf>"
  ) {
    val contextName = Opts.option[String]("context-name", "Context Name").withDefault(user)
    contextName.map { arg =>
      for
        contextEntries <- getContextEntries(arg)
        ncf            <- updateContextEntries(arg, contextEntries)
        _              <- IO.pure(os.write.over(
                            contextFilePath,
                            contextEntries.copy(entries = contextEntries.entries + (arg -> ncf)).asJson.spaces2
                          ))

        _          <- IO.println(s"Your DWN Context has been initialized for $arg with DID: ${ncf.did}")
        privateKey <- getPrivateKey(keyStorePath, arg, "password")
        publicKey  <- getPublicKey(contextFilePath, arg)
        encMsg     <- publicKey.map(pk => encryptMessage("Hello World", pk)).getOrElse(IO.pure(""))
        _          <- IO.println(s"Encrypted Message: $encMsg")
        decMsg     <- decryptMessage(encMsg, privateKey)
        _          <- IO.println(s"Decrypted Message: $decMsg")
        _          <- generateQRCode(s"${ncf.did}", userDir / "DID_Me" / s"$arg.png")


      // _ <- IO.println(s"Your Public: ${getPublicKeyFromBase64(publicKey.getOrElse(""))}")
      yield ()
    }
  }

  val deleteCommand: Command[IO[Unit]] = Command("delete", "Delete your DWN Context for a given context name") {
    val contextName = Opts.option[String]("context-name", "Context Name").withDefault(user)
    contextName.map { arg =>
      for
        contextEntries <- getContextEntries(arg)
        ncf            <- updateContextEntries(arg, ContextEntries(contextEntries.entries - arg))
        _              <- IO.pure(os.write.over(contextFilePath, ncf.asJson.spaces2))
        _              <- IO.println(s"Your DWN Context for $arg has been deleted")
      yield ()
    }
  }

  val getCommand: Command[IO[Unit]] = Command("get", "Get context for a given context name") {
    val contextName = Opts.option[String]("context-name", "Context Name").withDefault(user)
    val outputPath  = Opts.option[String]("output-path", "Output Path").withDefault(userDir.toString())
    contextName.map { arg =>
      for
        contextEntries <- readContextEntries(contextFilePath)
        did            <- fetchDID(arg).map(_.getOrElse(""))
        // create a qr-code for the did
        _              <- IO.println(s"The DID for context $arg: $did")
      yield ()
    }
  }

  val relayCommand: Command[IO[Unit]] = Command("relay", "Relay something") {
    Opts.unit.map { _ =>
      for
        // Logic for the "relay" command
        _ <- IO.println("Relaying something")
      yield ()
    }
  }

  def main: Opts[IO[ExitCode]] = {
    val helpFlag                = Opts.flag("help", "Show help information").orFalse
    val command: Opts[IO[Unit]] = Opts.subcommand(initCommand) orElse Opts.subcommand(
      deleteCommand
    ) orElse Opts.subcommand(getCommand) orElse Opts.subcommand(relayCommand)
    (command, helpFlag).mapN {
      case (cmd, true)  => cmd.as(ExitCode.Success)
      case (cmd, false) => cmd.as(ExitCode.Success)
    }
  }
