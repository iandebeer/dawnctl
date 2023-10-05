package xyz.didx

import java.security.KeyStore
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Key

import cats.implicits._
import cats.effect.IO

import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec
import java.security.KeyStore.TrustedCertificateEntry
import java.util.Base64
import java.security.PublicKey
import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.*
import com.nimbusds.jose.jwk.*
import com.nimbusds.jose.jwk.gen.*
import com.nimbusds.jose.jwk.JWKSet
import java.nio.file.Paths
import java.io.FileOutputStream
import java.io.FileInputStream
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.cert.X509Certificate
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import java.math.BigInteger
import java.util.Date
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import scala.util.Try
import scala.util.{Success, Failure}

object Crypto:
  Security.addProvider(new BouncyCastleProvider())
  // if the keystore file does not exist, create a new keystore file
  def getKeyStore(password: String, keyStorePath: os.Path): IO[Either[Error, KeyStore]] =
    if (!os.exists(keyStorePath))
      createKeyStore(password, keyStorePath.toString())
    else
      loadKeyStore(password, keyStorePath.toString())
  // create a java keystore object

  def createKeyStore(password: String, keystorePath: String): IO[Either[Error, KeyStore]] = IO {
    val keyStore = KeyStore.getInstance("JKS")
    Try {
      keyStore.load(null, password.toCharArray)
      val keystoreFile         = Paths.get(keystorePath).toFile
      val keystoreOutputStream = new FileOutputStream(keystoreFile)
      keyStore.store(keystoreOutputStream, password.toCharArray)
      keystoreOutputStream.close()
    } match
      case Success(_)         => keyStore.asRight[Error]
      case Failure(exception) => Error(exception.getMessage()).asLeft[KeyStore]
  }

  def loadKeyStore(password: String, keystorePath: String): IO[Either[Error, KeyStore]] = IO {
    val keyStore = KeyStore.getInstance("JKS")
    Try {
      val keystoreFile        = Paths.get(keystorePath).toFile
      val keystoreInputStream = new FileInputStream(keystoreFile)
      keyStore.load(keystoreInputStream, password.toCharArray)
      keystoreInputStream.close()
    } match
      case Success(_)         => keyStore.asRight[Error]
      case Failure(exception) => Error(exception.getMessage()).asLeft[KeyStore]
  }

  // create a RSA key pair using java.security.KeyPairGenerator
  def createKeyPairRSA(): IO[Either[Error, KeyPair]] = IO {
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC")
    keyPairGenerator.initialize(2048)
    Try {
      keyPairGenerator.generateKeyPair()
    } match
      case Success(keyPair)   => keyPair.asRight[Error]
      case Failure(exception) => Error(exception.getMessage()).asLeft[KeyPair]
  }

  // create a ED525519 key pair using net.i2p.crypto.eddsa.EdDSASecurityProvider
  def createKeyPair(alias: String): IO[Either[Error, ECKey]] =
    for {
      // keyStore <- getKeyStore("password", keystorePath)
      jwk <- Try {
               new ECKeyGenerator(Curve.P_384).keyID(alias).generate()
             } match
               case Success(jwk)       => IO(jwk.asRight[Error])
               case Failure(exception) => IO(Error(exception.getMessage()).asLeft[ECKey])

    } yield jwk // .computeThumbprint().toString()

  // save the JWKSet to a file
  def saveToJWKSet(jwk: ECKey): IO[Either[Error, Unit]] = IO {
    Try {
      val keystoreFile         = keyStorePath.toIO
      val keystoreOutputStream = new java.io.FileOutputStream(keystoreFile)
      val pubJson              = new JWKSet(jwk).toPublicJWKSet()
      keystoreOutputStream.write(pubJson.toString().getBytes())
      keystoreOutputStream.close()
    } match
      case Success(_)         => ().asRight[Error]
      case Failure(exception) => Error(exception.getMessage()).asLeft[Unit]
  }

  // store the private key keystore
  def storePrivateKey(
    keyStore: KeyStore,
    keyPair: ECKey,
    alias: String,
    password: String,
    certificate: X509Certificate
  ): IO[Either[Error, Unit]] = IO {
    Try {
      val certificateChain     = Array[java.security.cert.Certificate](certificate)
      keyStore.setKeyEntry(s"$alias", keyPair.toPrivateKey(), password.toCharArray(), certificateChain)
      val keystoreFile         = keyStorePath.toIO
      val keystoreOutputStream = new java.io.FileOutputStream(keystoreFile)
      keyStore.store(keystoreOutputStream, password.toCharArray)
      keystoreOutputStream.close()
    } match
      case Success(_)         => ().asRight[Error]
      case Failure(exception) => Error(exception.getMessage()).asLeft[Unit]
  }

  def getPrivateKey(alias: String, password: String): IO[Either[Error, ECPrivateKey]] =
    for
      keyStore   <- getKeyStore(password, keyStorePath)
      privateKey <- IO(keyStore.map { ks =>
                      ks.getKey(alias, password.toCharArray())
                        .asInstanceOf[ECPrivateKey]
                    })
    yield privateKey

  // get the private key from keystore
  def getPrivateKey(keyStore: KeyStore, alias: String, password: String): IO[Either[Error, Key]] = IO {
    Try {
      keyStore.getKey(alias, password.toCharArray())
    } match
      case Success(key)       => key.asRight[Error]
      case Failure(exception) => Error(exception.getMessage()).asLeft[Key]
  }

  // encrypt the message using nimbus-jose-jwt library and return the encrypted message as base64 string
  def decryptMessage(encryptedMessage: String, privateKey: ECPrivateKey): IO[Either[Error, String]] = IO {

    Try {
      val jweObject = JWEObject.parse(encryptedMessage)
      jweObject.decrypt(new ECDHDecrypter(privateKey))
      jweObject.getPayload().toString()
    } match
      case Success(message)   => message.asRight[Error]
      case Failure(exception) => Error(exception.getMessage()).asLeft[String]

  }

def encryptMessage(message: String, publicKey: ECPublicKey): IO[Either[Error, String]] = IO {
  Try {
    val o = new JWEObject(
      new JWEHeader.Builder(JWEAlgorithm.ECDH_ES_A256KW, com.nimbusds.jose.EncryptionMethod.A256GCM)
        .keyID(publicKey.toString())
        .build(),
      new Payload(message)
    )
    o.encrypt(new ECDHEncrypter(publicKey))
    o.serialize()
  } match
    case Success(s)         => s.asRight[Error]
    case Failure(exception) => Error(exception.getMessage()).asLeft[String]
}

//sign message using nimbus-jose-jwt library and return the signed message as base64 string
def signMessage(message: String, privateKey: ECPrivateKey): IO[Either[Error, String]] = IO {
  Try {
    val jwsObject = new JWSObject(
      new JWSHeader.Builder(JWSAlgorithm.ES384).keyID(privateKey.toString()).build(),
      new Payload(message)
    )
    jwsObject.sign(new ECDSASigner(privateKey))
    jwsObject.serialize()
  } match
    case Success(s)         => s.asRight[Error]
    case Failure(exception) => Error(exception.getMessage()).asLeft[String]
}

//validate the signature of the message using nimbus-jose-jwt library and return the boolean value
def validateSignature(message: String, publicKey: ECPublicKey): IO[Either[Error, String]] = IO {
  val jwsObject = JWSObject.parse(message)
  Try(jwsObject.verify(new ECDSAVerifier(publicKey))) match
    case Success(_)         => jwsObject.getPayload().toString().asRight[Error]
    case Failure(exception) => Error(exception.getMessage()).asLeft[String]
}

// decrypt the message using nimbus-jose-jwt library and return the encrypted message as base64 string
def decryptMessage(message: String, privateKey: ECPrivateKey): IO[Either[Error, String]] = IO {
  val jweObject = JWEObject.parse(message)
  Try(jweObject.decrypt(new ECDHDecrypter(privateKey))) match
    case Success(_)         => jweObject.getPayload().toString().asRight[Error]
    case Failure(exception) => Error(exception.getMessage()).asLeft[String]
}

def createSelfSignedCertificate(alias: String): IO[Either[Error, X509Certificate]] = IO {
  Try {
    Security.addProvider(new BouncyCastleProvider())
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC")
    keyPairGenerator.initialize(2048)
    val keyPair          = keyPairGenerator.generateKeyPair()
    val subject          = new X500Name(s"CN=$alias")
    val issuer           = subject
    val serialNumber     = BigInteger.valueOf(System.currentTimeMillis())
    val notBefore        = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000) // 1 day ago
    val notAfter         =
      new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000) // 1 year from now
    val pubKey        =
      org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded)
    val publicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(pubKey)
    val certBuilder   = new X509v3CertificateBuilder(
      issuer,
      serialNumber,
      notBefore,
      notAfter,
      subject,
      publicKeyInfo
    )
    val contentSigner = JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate())
    val certHolder    = certBuilder.build(contentSigner)
    val certConverter = JcaX509CertificateConverter()
    certConverter.getCertificate(certHolder)
  } match
    case Success(certificate) => certificate.asRight[Error]
    case Failure(exception)   => Error(exception.getMessage()).asLeft[X509Certificate]
}

def storeCertificate(
  keyStore: KeyStore,
  certificate: X509Certificate,
  alias: String,
  password: Array[Char]
): IO[Either[Error, Unit]] =
  IO {
    Try {
      keyStore.setCertificateEntry(alias, certificate)
    } match
      case Success(_)         => ().asRight[Error]
      case Failure(exception) => Error(exception.getMessage()).asLeft[Unit]
  }
  // Save the keystore to a file or perform any other necessary operations

def getPublicKeyFromBase64(base64String: String): IO[Either[Exception, PublicKey]] =
  val keyBytes   = Base64.getDecoder.decode(base64String)
  val keySpec    = new X509EncodedKeySpec(keyBytes)
  val keyFactory = KeyFactory.getInstance("EdDSA")
  IO(keyFactory.generatePublic(keySpec).asRight[Exception])
