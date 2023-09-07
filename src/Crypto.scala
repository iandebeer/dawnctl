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


object Crypto:
    //create a java keystore object
    def createKeyStore(password: String): IO[KeyStore] = IO.delay {
        val keyStore = KeyStore.getInstance("JKS")
        keyStore.load(null, password.toCharArray)
        keyStore
    }


    // create a pki key pair using nimbus-jose-jwt library 
    def createKeyPair(): IO[KeyPair] = IO.delay {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(2048)
        keyPairGenerator.generateKeyPair()
    }
   
    // store the private key keystore
    def storePrivateKey(keyStore: KeyStore, keyPair: KeyPair, alias: String, password: String): IO[Unit] = IO.delay {
        keyStore.setKeyEntry(alias, keyPair.getPrivate(), password.toCharArray(), null)
    }



    // get the private key from keystore
    def getPrivateKey(keyStore: KeyStore, alias: String, password: String): IO[Key] = IO.delay {
        val privateKey = keyStore.getKey(alias, password.toCharArray())
        privateKey

    }
    // encrypt the message using nimbus-jose-jwt library and return the encrypted message as base64 string    
    def encryptMessage(message: String, publicKey: RSAPublicKey): IO[String] = IO.delay {
        val jweObject = new JWEObject(
            new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP, com.nimbusds.jose.EncryptionMethod.A256GCM)
                .keyID(publicKey.toString())
                .build(),
            new Payload(message)
        )
        jweObject.encrypt(new RSAEncrypter(publicKey))
        jweObject.serialize()
    }