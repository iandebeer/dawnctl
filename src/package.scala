package xyz

import java.net.URI
import io.circe.*
import io.circe.parser.*
import io.circe.syntax.*
import io.circe.Encoder.encodeUnit
import io.circe.generic.semiauto.*
import io.circe.Encoder.encodeJsonObject
package object didx:

  val prompt      = ">> "
  val exitCommand = "exit"

  val user            = System.getProperty("user.name")
  val userDir         = os.home
  val dawnDir         = userDir / ".config" / "dawn"
  val contextFilePath = dawnDir / "dawn.conf"
  val keyStorePath    = dawnDir / "keystore.jks"
  val dwnUrl          = "https://dwn.dawn.dev.didxtech.com/dawn.dwn.api.v1.DwnApiService/CreateDwn"

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

  case class DidDetails(
    didDocument: DidDocument,
    didDocumentMetadata: DidDocumentMetadata
  )

  given Encoder[DidDetails] = deriveEncoder[DidDetails]
  given Decoder[DidDetails] = deriveDecoder[DidDetails]
  case class DidDocument(
    authentication: List[String],
    id: String,
    service: List[Service],
    verificationMethod: List[VerificationMethod]
  )

  given Encoder[DidDocument] = deriveEncoder[DidDocument]
  given Decoder[DidDocument] = deriveDecoder[DidDocument]

  case class Service(
    id: String,
    serviceEndpoint: ServiceEndpoint,
    `type`: String
  )

  given Encoder[Service] = deriveEncoder[Service]
  given Decoder[Service] = deriveDecoder[Service]

  case class ServiceEndpoint(
    nodes: List[String]
  )

  given Encoder[ServiceEndpoint] = deriveEncoder[ServiceEndpoint]
  given Decoder[ServiceEndpoint] = deriveDecoder[ServiceEndpoint]

  case class VerificationMethod(
    controller: String,
    id: String,
    publicKeyJwk: PublicKeyJwk,
    `type`: String
  )

  given Encoder[VerificationMethod] = deriveEncoder[VerificationMethod]
  given Decoder[VerificationMethod] = deriveDecoder[VerificationMethod]

  case class PublicKeyJwk(
    crv: String,
    kty: String,
    x: String
  )

  given Encoder[PublicKeyJwk] = deriveEncoder[PublicKeyJwk]
  given Decoder[PublicKeyJwk] = deriveDecoder[PublicKeyJwk]
  case class DidDocumentMetadata(
    equivalentId: List[String],
    method: Method
  )

  given Encoder[DidDocumentMetadata] = deriveEncoder[DidDocumentMetadata]
  given Decoder[DidDocumentMetadata] = deriveDecoder[DidDocumentMetadata]
  case class Method(
    recoveryCommitment: String,
    updateCommitment: String
  )

  case class Tenant(
    tenantId: TenantId,
    userDetails: Map[String, String]
  )

  given Encoder[Tenant] = deriveEncoder[Tenant]
  given Decoder[Tenant] = deriveDecoder[Tenant]

  case class TenantId(
    dwnDid: String,
    dwnDidEquivalent: String,
    ownerDid: String
  )

  given Encoder[TenantId] = deriveEncoder[TenantId]
  given Decoder[TenantId] = deriveDecoder[TenantId]

  case class Root(
    didDetails: DidDetails,
    tenant: Tenant
  )

  given Encoder[Root] = deriveEncoder[Root]
  given Decoder[Root] = deriveDecoder[Root]
