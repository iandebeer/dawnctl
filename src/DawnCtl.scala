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
import cats.data.EitherT
import scala.io.StdIn.readLine

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
  def getUserInput: IO[Int]   = IO {
    val input = readLine(prompt)
    input.toInt
  }

  def getChannelType: IO[ChannelType] =
    val valid = List(1, 2, 3, 4, 5, 6)
    for {
      _     <- IO.println(
                 "Select a chat agent: \n 1. Slack \n 2. WhatsApp \n 3. Signal \n 4. Telegram \n 5. Email \n 6. SMS  "
               )
      //   _ <- IO.print(prompt)
      input <- getUserInput
      // _ <- handleUserInput(input)
      c     <- if (valid.contains(input))
                 IO(ChannelType.fromOrdinal(input - 1))
               else
                 IO.println("Invalid input")
                 getChannelType
      // input != 0) loop else IO.unit
    } yield c

  val initCommand: Command[IO[Unit]] = Command(
    "init",
    "Initialize your DWN Context. A DID generated by the DWN Network will be stored in the Context file <$user.home/.dawn/dawn.conf>"
  ) {
    val contextName = Opts.option[String]("context-name", "Context Name").withDefault(user)
    contextName.map { arg =>
      val channel =
        for
          c <- getChannelType
          _ <- IO.println(s"\nSelected Channel: ${c.toString()}}")
        yield c
      val x       =
        for
          _              <- EitherT.right(IO.println(s"\nInitializing your DWN Context for $arg"))
          contextEntries <- EitherT(getContextEntries(arg))
          _              <- EitherT.right(
                              IO.println(s"\nYour DWN Context for $arg created at: $contextFilePath")
                            )
          channelType    <- EitherT.right(channel)

          ncf        <- EitherT(addNewContext(arg, contextEntries, channelType))
          _          <- EitherT.right(IO.println(s"\nYour DWN Context has been initialized for $arg with DID: ${ncf.did}"))
          privateKey <- EitherT(getPrivateKey(arg, "password"))
          publicKey  <- EitherT(getPublicKey(contextFilePath, arg))
          pk         <- EitherT.fromOption(publicKey, java.lang.Error("Invalid Private Key"))

          // test encryption and signing

          encMsg <- EitherT(encryptMessage("Hello World!", pk))
          _      <- EitherT.rightT(println(s"\nEncrypted Message: \n$encMsg"))
          sig    <- EitherT(signMessage(encMsg, privateKey))
          _      <- EitherT.rightT(println(s"\nSignature: \n$sig"))
          valMsg <- EitherT(validateSignature(sig, pk))
          msg    <- EitherT(decryptMessage(valMsg, privateKey))
          _      <- EitherT.rightT(println(s"\nDecrypted Verified Message: \n$msg"))
        yield ()

      for
        y <- x.value
        _ <- y match
               case Left(err) => IO.println(s"Error: $err")
               case Right(_)  => IO.println(s"\nYour DWN Context has been initialized for $arg")
      yield ()
    }
  }

  val deleteCommand: Command[IO[Unit]] = Command("delete", "Delete your DWN Context for a given context name") {
    val contextName = Opts.option[String]("context-name", "Context Name").withDefault(user)
    contextName.map { arg =>
      for
        ncf <- deleteContextEntries(arg)
        _   <- IO.println(s"Your DWN Context for $arg has been deleted")
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
