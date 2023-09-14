package xyz.didx

import java.security.KeyStore
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Key

import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.crypto.RSAEncrypter
import com.nimbusds.jose.jwk.RSAKey

import cats.implicits._
import cats.effect.IO
import javax.crypto.Cipher
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.Payload
import java.security.interfaces.RSAPublicKey
import java.security.cert.X509Certificate
import java.io.FileOutputStream
import java.nio.file.{Path, Paths}
import os._


import org.bouncycastle.asn1.x500.X500Name
import java.math.BigInteger
import java.util.Date
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import java.io.FileInputStream
import java.security.spec.RSAPublicKeySpec
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec
import java.security.KeyStore.TrustedCertificateEntry



object Crypto:
    //if the keystore file does not exist, create a new keystore file
    def getKeyStore(password: String, keyStorePath: os.Path): IO[KeyStore] = 
        if (!os.exists(keyStorePath)) 
            createKeyStore(password, keyStorePath.toString())
        else 
            loadKeyStore(password, keyStorePath.toString())
    //create a java keystore object

    def createKeyStore(password: String, keystorePath: String): IO[KeyStore] = IO.pure {
        val keyStore = KeyStore.getInstance("JKS")
        keyStore.load(null, password.toCharArray)
        val keystoreFile = Paths.get(keystorePath).toFile
        val keystoreOutputStream = new FileOutputStream(keystoreFile)
        keyStore.store(keystoreOutputStream, password.toCharArray)
        keystoreOutputStream.close()
        keyStore
    }

    def loadKeyStore(password: String, keystorePath: String): IO[KeyStore] = IO.pure {
        val keyStore = KeyStore.getInstance("JKS")
        val keystoreFile = Paths.get(keystorePath).toFile
        val keystoreInputStream = new FileInputStream(keystoreFile)
        keyStore.load(keystoreInputStream, password.toCharArray)
        keystoreInputStream.close()
        keyStore
    }

    // create a RSA key pair using java.security.KeyPairGenerator
    def createKeyPairRSA(): IO[KeyPair] = IO.pure {

      Security.addProvider(new BouncyCastleProvider())
      val keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC")
        keyPairGenerator.initialize(2048)
        keyPairGenerator.generateKeyPair()
    }

    // create a ED525519 key pair using net.i2p.crypto.eddsa.EdDSASecurityProvider
    def createKeyPairED25519(): IO[KeyPair] = IO.pure {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider())
        val keyPairGenerator = KeyPairGenerator.getInstance("Ed25519", "BC")
        keyPairGenerator.initialize(256)
        keyPairGenerator.generateKeyPair()
    }

   
    // store the private key keystore
    def storePrivateKey(keyStore: KeyStore, keyPair: KeyPair, alias: String, password: String, certificate: X509Certificate): IO[Unit] = IO.pure {
       // keyStore.setKeyEntry(alias, keyPair.getPrivate(), password.toCharArray(), null)
       val certificateChain = Array[java.security.cert.Certificate](certificate)
       keyStore.setKeyEntry(alias, keyPair.getPrivate(), password.toCharArray(), certificateChain)
       

    }

    // get the private key from keystore
    def getPrivateKey(keyStore: KeyStore, alias: String, password: String): IO[Key] = IO.pure {
        val privateKey = keyStore.getKey(alias, password.toCharArray())
        privateKey

    }

  
    // encrypt the message using nimbus-jose-jwt library and return the encrypted message as base64 string    
    def encryptMessage(message: String, publicKey: RSAPublicKey): IO[String] = IO.pure {
        val jweObject = new JWEObject(
            new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP, com.nimbusds.jose.EncryptionMethod.A256GCM)
                .keyID(publicKey.toString())
                .build(),
            new Payload(message)
        )
        jweObject.encrypt(new RSAEncrypter(publicKey))
        jweObject.serialize()
    }
    def createSelfSignedCertificate(alias: String): IO[X509Certificate] = IO.pure {
        Security.addProvider(new BouncyCastleProvider())
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC")
        keyPairGenerator.initialize(2048)
        val keyPair = keyPairGenerator.generateKeyPair()
        val subject = new X500Name(s"CN=$alias")
        val issuer = subject
        val serialNumber = BigInteger.valueOf(System.currentTimeMillis())
        val notBefore = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000) // 1 day ago
        val notAfter = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000) // 1 year from now
        val pubKey = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded)
        val publicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(pubKey)   
        val certBuilder = new X509v3CertificateBuilder(issuer, serialNumber, notBefore, notAfter, subject, publicKeyInfo)
        val contentSigner = JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate())
        val certHolder = certBuilder.build(contentSigner)
        val certConverter = JcaX509CertificateConverter()
        certConverter.getCertificate(certHolder)
    }

    def storeCertificate(keyStore: KeyStore, certificate: X509Certificate, alias: String, password: Array[Char]): IO[Unit] = {
        IO.pure(keyStore.setCertificateEntry(alias, certificate))
        // Save the keystore to a file or perform any other necessary operations
        }
