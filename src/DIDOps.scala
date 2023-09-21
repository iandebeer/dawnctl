package xyz.didx

import cats.effect.*
import cats.syntax.all.*
import Crypto.*
import ContextFileOps.*
import com.nimbusds.jose.jwk.JWKSet
import java.awt.image.BufferedImage
import java.io.File
import javax.imageio.ImageIO
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

object DIDOps:
  def generateDid(alias: String): IO[(String, String)] =
    for
      keyStore    <- getKeyStore("password", keyStorePath)
      keyPair     <- createKeyPairRSA()
      certificate <- createSelfSignedCertificate(alias)
      _           <- storeCertificate(keyStore, certificate, alias, "password".toArray[Char])

      kp <- createKeyPair(alias, keyStorePath)
      _  <- storePrivateKey(keyStorePath, keyStore, kp, alias, "password", certificate)
    // _  <- storePublicKey(contextFilePath, alias, kp.getPublic().toString())
    yield (s"did:key:${kp.computeThumbprint().toString()}", new JWKSet(kp).toPublicJWKSet().toString())

  def fetchDID(alias: String): IO[Either[Throwable, String]] =
    for

      keyStore <- getKeyStore("password", keyStorePath)
      pk       <- getPublicKey(contextFilePath, alias)

    /*   getPublicKey(contextFilePath, alias).unsafeRunSync() match
        case Some(pk) => s"did:key:$pk".asRight[Throwable].pure[IO]
        case None     => Left(new Exception("Invalid Public Key")).pure[IO] */
    yield s"did:key:$pk".asRight[Throwable]

  def generateQRCode(text: String, filePath: os.Path): IO[Unit] =
   
    val qrCodeWriter = new QRCodeWriter()
    val hints = new java.util.HashMap[EncodeHintType, Any]()
    hints.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.L)
    val bitMatrix = qrCodeWriter.encode(text, BarcodeFormat.QR_CODE, 200, 200, hints)
    val bufferedImage = new BufferedImage(200, 200, BufferedImage.TYPE_INT_RGB)
    for (x <- 0 until 200) {
        for (y <- 0 until 200) {
        bufferedImage.setRGB(x, y, if (bitMatrix.get(x, y)) 0xFF000000 else 0xFFFFFFFF)
        }
    }
    for 
      _ <- IO.pure(os.makeDir.all(filePath / os.up))
      _ <- IO.pure(ImageIO.write(bufferedImage, "png", new File(filePath.toString())))
    yield ()
