package xyz

import java.net.URI
import io.circe.*
import io.circe.parser.*
import io.circe.syntax.*
import io.circe.Encoder.encodeUnit
import io.circe.generic.semiauto.*
import io.circe.Encoder.encodeJsonObject
package object didx:

  enum ChannelType(agent: URI):
    case Slack    extends ChannelType(URI("https://slack.com/api/chat.postMessage"))
    case WhatsApp extends ChannelType(URI("https://api.whatsapp.com/send"))
    case Signal   extends ChannelType(URI("https://signal.org/api/v1/send"))
    case Telegram extends ChannelType(URI("https://api.telegram.org/bot"))
    case Email    extends ChannelType(URI("smtp://smtp.gmail.com:587"))
    case SMS      extends ChannelType(URI(
          "https://api.twilio.com/2010-04)-01/Accounts/ACXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX/Messages.json"
        ))
    def fromString(s: String): Either[Throwable, ChannelType] =
      s match
        case "slack"    => Right(Slack)
        case "whatsapp" => Right(WhatsApp)
        case "signal"   => Right(Signal)
        case "telegram" => Right(Telegram)
        case "email"    => Right(Email)
        case "sms"      => Right(SMS)
        case _          => Left(new Exception("Invalid Channel Type"))
    override def toString(): String                           =
      this match
        case Slack    => "slack"
        case WhatsApp => "whatsapp"
        case Signal   => "signal"
        case Telegram => "telegram"
        case Email    => "email"
        case SMS      => "sms"

  case class Channels(channel: String, channelDid: String)
  given Encoder[Channels] = deriveEncoder[Channels]
  given Decoder[Channels] = deriveDecoder[Channels]
  // case class Context(did: String)
  case class KeyPair(
    kty: String,
    crv: String,
    kid: String,
    x: String,
    y: String
  )

  given Encoder[KeyPair] = deriveEncoder[KeyPair]
  given Decoder[KeyPair] = deriveDecoder[KeyPair]

  case class KeyPairs(keys: List[KeyPair])

  given Encoder[KeyPairs] = deriveEncoder[KeyPairs]
  given Decoder[KeyPairs] = deriveDecoder[KeyPairs]
  case class ContextEntry(
    did: String,
    keyStorePath: Option[String] = None,
    publicKey: Option[String] = None,
    keypair: Option[KeyPair] = None
  )

  given Encoder[ContextEntry] = deriveEncoder[ContextEntry]
  given Decoder[ContextEntry] = deriveDecoder[ContextEntry]

  case class ContextEntries(entries: Map[String, ContextEntry])

  given Encoder[ContextEntries] = deriveEncoder[ContextEntries]
  given Decoder[ContextEntries] = deriveDecoder[ContextEntries]

  val prompt      = ">> "
  val exitCommand = "exit"

  val user            = System.getProperty("user.name")
  val userDir         = os.home
  val dawnDir         = userDir / ".dawn"
  val contextFilePath = dawnDir / "dawn.conf"
  val keyStorePath    = dawnDir / "keystore.jks"
