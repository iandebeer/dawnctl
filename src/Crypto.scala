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

object Crypto:
  Security.addProvider(new BouncyCastleProvider())
  // if the keystore file does not exist, create a new keystore file
  def getKeyStore(password: String, keyStorePath: os.Path): IO[KeyStore] =
    if (!os.exists(keyStorePath))
      createKeyStore(password, keyStorePath.toString())
    else
      loadKeyStore(password, keyStorePath.toString())
  // create a java keystore object

  def createKeyStore(password: String, keystorePath: String): IO[KeyStore] = IO.pure {
    val keyStore             = KeyStore.getInstance("JKS")
    keyStore.load(null, password.toCharArray)
    val keystoreFile         = Paths.get(keystorePath).toFile
    val keystoreOutputStream = new FileOutputStream(keystoreFile)
    keyStore.store(keystoreOutputStream, password.toCharArray)
    keystoreOutputStream.close()
    keyStore
  }

  def loadKeyStore(password: String, keystorePath: String): IO[KeyStore] = IO.pure {
    val keyStore            = KeyStore.getInstance("JKS")
    val keystoreFile        = Paths.get(keystorePath).toFile
    val keystoreInputStream = new FileInputStream(keystoreFile)
    keyStore.load(keystoreInputStream, password.toCharArray)
    keystoreInputStream.close()
    keyStore
  }

  // create a RSA key pair using java.security.KeyPairGenerator
  def createKeyPairRSA(): IO[KeyPair] = IO.pure {
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC")
    keyPairGenerator.initialize(2048)
    keyPairGenerator.generateKeyPair()
  }

  // create a ED525519 key pair using net.i2p.crypto.eddsa.EdDSASecurityProvider
  def createKeyPair(alias: String, keystorePath: os.Path): IO[ECKey] =
    for {
      // keyStore <- getKeyStore("password", keystorePath)
      jwk <- IO.pure(new ECKeyGenerator(Curve.P_384)
               .keyID(alias)
               .generate())
      // _ <- IO.pure(jwk.toPublicJWK().toString())
      // _ <- IO.pure(jwk.getKeyStore().store(new java.io.FileOutputStream(keystorePath.toIO), "password".toCharArray()))
      // _ <- saveToJWKSet(jwk, keystorePath)
      /*   publicJWK <- jwk.getKeyStore()
    val jwkSet = JWKSet.load(keyStore, null)
    val keystoreOutputStream = new java.io.FileOutputStream(keystoreFile)
    keystoreOutputStream.close()
    jwkSet.getKeyByKeyId(alias).toOctetKeyPair().toKeyPair()
       */
      // jwk.toKeyPair()
    } yield jwk // .computeThumbprint().toString()

  // save the JWKSet to a file
  def saveToJWKSet(jwk: ECKey, keystorePath: os.Path): IO[Unit] = IO.pure {
    val keystoreFile         = keystorePath.toIO
    val keystoreOutputStream = new java.io.FileOutputStream(keystoreFile)
    // val json                 = new JWKSet(jwk).toJSONObject()
    val pubJson              = new JWKSet(jwk).toPublicJWKSet()
    keystoreOutputStream.write(pubJson.toString().getBytes())
    keystoreOutputStream.close()
  }

  // store the private key keystore
  def storePrivateKey(
    keystorePath: os.Path,
    keyStore: KeyStore,
    keyPair: ECKey,
    alias: String,
    password: String,
    certificate: X509Certificate
  ): IO[Unit] = IO.pure {
    val certificateChain     = Array[java.security.cert.Certificate](certificate)
    keyStore.setKeyEntry(s"$alias", keyPair.toPrivateKey(), password.toCharArray(), certificateChain)
    val keystoreFile         = keystorePath.toIO
    val keystoreOutputStream = new java.io.FileOutputStream(keystoreFile)
    keyStore.store(keystoreOutputStream, password.toCharArray)
    keystoreOutputStream.close()
  }

  def getPrivateKey(keyStorePath: os.Path, alias: String, password: String): IO[ECPrivateKey] =
    for
      keyStore   <- getKeyStore(password, keyStorePath)
      privateKey <- IO.pure(keyStore.getKey(alias, password.toCharArray()))
      ecKey      <- IO.pure(privateKey.asInstanceOf[ECPrivateKey])
    yield ecKey

  // get the private key from keystore
  def getPrivateKey(keyStore: KeyStore, alias: String, password: String): IO[Key] = IO.pure {
    val privateKey = keyStore.getKey(alias, password.toCharArray())
    privateKey

  }

  // encrypt the message using nimbus-jose-jwt library and return the encrypted message as base64 string
  def encryptMessage(message: String, publicKey: ECPublicKey): IO[String] = IO.pure {
    val jweObject = new JWEObject(
      new JWEHeader.Builder(JWEAlgorithm.ECDH_ES_A256KW, com.nimbusds.jose.EncryptionMethod.A256GCM)
        .keyID(publicKey.toString())
        .build(),
      new Payload(message)
    )
    jweObject.encrypt(new ECDHEncrypter(publicKey))
    jweObject.serialize()
  }

  // decrypt the message using nimbus-jose-jwt library and return the encrypted message as base64 string
  def decryptMessage(message: String, privateKey: ECPrivateKey): IO[String] = IO.pure {
    val jweObject = JWEObject.parse(message)
    jweObject.decrypt(new ECDHDecrypter(privateKey))
    jweObject.getPayload().toString()
  }

  def createSelfSignedCertificate(alias: String): IO[X509Certificate] = IO.pure {
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
  }

  def storeCertificate(
    keyStore: KeyStore,
    certificate: X509Certificate,
    alias: String,
    password: Array[Char]
  ): IO[Unit] =
    IO.pure(keyStore.setCertificateEntry(alias, certificate))
    // Save the keystore to a file or perform any other necessary operations

  def getPublicKeyFromBase64(base64String: String): IO[Either[Exception, PublicKey]] =
    val keyBytes   = Base64.getDecoder.decode(base64String)
    val keySpec    = new X509EncodedKeySpec(keyBytes)
    val keyFactory = KeyFactory.getInstance("EdDSA")
    IO.pure(keyFactory.generatePublic(keySpec).asRight[Exception])
