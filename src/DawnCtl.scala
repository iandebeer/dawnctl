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

object DawnCtl extends CommandIOApp("dawnctl", "A command-line interface to your DWN Context") : 
  enum ChannelType(agent: URI):
    case Slack extends ChannelType(URI("https://slack.com/api/chat.postMessage"))
    case WhatsApp extends ChannelType(URI("https://api.whatsapp.com/send"))
    case Signal extends ChannelType(URI("https://signal.org/api/v1/send"))
    case Telegram extends ChannelType(URI("https://api.telegram.org/bot"))
    case Email extends ChannelType(URI("smtp://smtp.gmail.com:587"))
    case SMS extends ChannelType(URI("https://api.twilio.com/2010-04)-01/Accounts/ACXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX/Messages.json"))
    def fromString(s: String): Either[Throwable, ChannelType] = 
      s match
        case "slack" => Right(Slack)
        case "whatsapp" => Right(WhatsApp)
        case "signal" => Right(Signal)
        case "telegram" => Right(Telegram)
        case "email" => Right(Email)
        case "sms" => Right(SMS)
        case _ => Left(new Exception("Invalid Channel Type"))
    override def toString(): String = 
      this match
        case Slack => "slack"
        case WhatsApp => "whatsapp"
        case Signal => "signal"
        case Telegram => "telegram"
        case Email => "email"
        case SMS => "sms"
    

  case class Channels(channel: String, channelDid: String)
  given Encoder[Channels] = deriveEncoder[Channels]
  given Decoder[Channels] = deriveDecoder[Channels]
 // case class Context(did: String)
  case class ContextEntry(did: String, keyStorePath: Option[String] = None, keyStorePassword: Option[String] = None, publicKey: Option[String] = None)

  given Encoder[ContextEntry] = deriveEncoder[ContextEntry]
  given Decoder[ContextEntry] = deriveDecoder[ContextEntry]

  case class ContextEntries(entries:Map[String,ContextEntry])

  given Encoder[ContextEntries] = deriveEncoder[ContextEntries]
  given Decoder[ContextEntries] = deriveDecoder[ContextEntries]


  val prompt = ">> "
  val exitCommand = "exit"
  
  def generateDid(alias: String): IO[Either[Throwable, String]] = {
    val keyStore = if (os.exists(keyStorePath)) {
      println(s"Keystore already exists at $keyStorePath")
      Crypto.loadKeyStore("password", keyStorePath.toString()).unsafeRunSync()
    } else {
      println(s"Creating keystore at $keyStorePath")
      Crypto.createKeyStore("password", keyStorePath.toString()).unsafeRunSync()
    }
    // Replace with your logic to generate the DID
    val pk: IO[Either[Throwable, RSAPublicKey]] = for 
      keyPair <- Crypto.createKeyPair()
      certificate <- Crypto.createSelfSignedCertificate(keyPair, alias)
      _ <- IO.println(s"Certificate: ${certificate}")
      _ <- Crypto.storeCertificate(keyStore, certificate, alias, "password".toArray[Char])
      _ <- Crypto.storePrivateKey(keyStore, keyPair, alias, "password")
      privateKey <- Crypto.getPrivateKey(keyStore, alias, "password")
      publicKey <- keyPair.getPublic() match
        case pk: RSAPublicKey => IO.pure(Right(pk))
        case _ => IO.pure(Left(new Exception("Invalid Public Key")))
    yield publicKey
    pk.map(k =>
      k match
        case Right(pk) => s"did:example:${pk.asRight[Throwable].pure[IO]}".asRight[Throwable]
        case Left(e) => e.asLeft[String]
    )
  }


   // s"did:example:${pk.asRight[Throwable].pure[IO]}")

  

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
  val user = System.getProperty("user.name")
  val userDir = os.home
  val dawnDir = userDir / ".dawn"
  val contextFilePath = dawnDir / "dawn.conf"
  val keyStorePath = dawnDir / "keystore.jks"
  def getContextEntries(name : String): IO[Either[Throwable, ContextEntries]] = 
    IO.pure(Try(os.exists(contextFilePath)).toEither.flatMap {
          case true => 
            //read the content of the file and parse the json to case class ContextFile 
            val contextEntries = Right(os.read(contextFilePath))
            for 
              content <- contextEntries
              json <- parse(content)
              cf <- json.as[ContextEntries]
            yield (cf)
          case false => 
            // create a new context file and generate a new did
            for 
              ncf <- Right(ContextEntries(Map()))
              _ <- Try(os.write(contextFilePath,ncf.asJson.spaces2,createFolders = true)).toEither
            yield ncf
        })
  def updateContextEntries(name : String, cf: ContextEntries): IO[(Either[Throwable, (ContextEntries, String)])] = 
    for    
      // check if the context name already exists and return the did or generate a new did
      did <- cf.entries.get(name) match {
        case Some(entry) => 
          println(s"Context for $name has already been initialized - ignore")   //Right(entry.did)
          IO.pure(Right(entry.did))
        case None => generateDid(name).attempt.map {
          case Right(did) => {
            println(s"Context for $name has been initialized with DID: ${did}")
            did
          }
          case Left(e) => Left(e)
        }
      }
    
      nce <- IO.pure(did match {
        case Right(did) => 
          // update the context file with the new did
          Right(cf.copy(entries = cf.entries + (name -> ContextEntry(did))))
        case Left(e) => Left(e)
      })
      result <- IO.pure(nce.flatMap { ce =>
         did.map { d =>(ce, d) }
        }) 
    yield result
          
        
  val initCommand: Command[Unit] = Command("init", "Initialize your DWN Context. A DID generated by the DWN Network will be stored in the Context file <$user.home/.dawn/dawn.conf>") {
    val contextName = Opts.option[String]("context-name", "Context Name").withDefault(user)
    (contextName).map { arg => {
      // Check if the context file already exists
      (for
        contextEntries<- getContextEntries(arg) 
        cf = contextEntries match
          case Right(ce) => ce
          case Left(e) => ContextEntries(Map())
        contextFile_Did <- updateContextEntries(arg,cf)
        ncf = contextFile_Did match
          case Right((c,_)) => c
          case Left(e) => ContextEntries(Map())
        d = contextFile_Did match
          case Right((_,did)) => did
          case Left(e) => generateDid(arg)
           // case Right(did) => did
            /* case Right(did) => did match
              case Right(did) => did
              case Left(e) => e
            case Left(e) => e */
          //}
        _ <- IO(Try(os.write.over(contextFilePath,ncf.asJson.spaces2)).toEither)
        _ <- IO.println(s"Your DWN Context has been initialized for $arg with DID: ${d}")

      yield ()).unsafeRunSync()
      
      }
    }
  }
  
  

  val deleteCommand = Command("delete", "Delete your DWN Context for a given context name") {
    val contextName = Opts.option[String]("context-name", "Context Name").withDefault(user)
    (contextName).map { arg =>
      for 
        // read the context file
        contextFile <- getContextEntries(arg)
        cf = contextFile match
          case Right(cf) => cf
          case Left(e) => ContextEntries(Map())
      // delete the entry dron the config file matching the context name
        ncf = cf.copy(entries = cf.entries - arg)
        _ <- IO.pure(Try(os.write.over(contextFilePath,ncf.asJson.spaces2)).toEither)
      yield ()
      println(s"Your DWN Context for $arg has been deleted")
    }
  }

  val getCommand = Command("get", "Get context for a given context name") {
    val contextName = Opts.option[String]("context-name", "Context Name").withDefault(user)
    val outputPath = Opts.option[String]("output-path", "Output Path").withDefault(user)
    (contextName).map { arg =>
      val did = for 
        // read the context file
        contextFile <- getContextEntries(arg)
        cf = contextFile match
          case Right(cf) => cf
          case Left(e) => ContextEntries(Map())
        d = cf.entries.get(arg) match {
            case Some(entry) => s"Your DWN Context for $arg is ${entry.did}"
            case None => s"Your DWN Context for $arg is not initialized"
          }
      yield (d)
      println(did)

    }
  }

  val relayCommand = Command("relay", "Relay something") {
    Opts.unit.map { _ =>
      // Logic for the "relay" command
      println("Relaying something")
    }
  }
 
  
  def main: Opts[IO[ExitCode]] = {
    val helpFlag = Opts.flag("help", "Show help information").orFalse
    val command: Opts[Unit] = Opts.subcommand(initCommand) orElse Opts.subcommand(deleteCommand) orElse Opts.subcommand(getCommand) orElse Opts.subcommand(relayCommand) 
    (command,helpFlag).mapN{
      case ((),true) => IO(println(helpInformation)).as(ExitCode.Success)
      case ((),false) => IO(println("Success")).as(ExitCode.Success)
    }
  }
