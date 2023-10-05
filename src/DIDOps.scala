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
import sttp.client3.*
import cats.effect.IO
import sttp.client3.asynchttpclient.cats.AsyncHttpClientCatsBackend
import sttp.client3.circe.*
import cats.data.EitherT


object DIDOps:
 /*  def generateDid(alias: String): IO[Either[Error, (String, String)]] =
    (for
      keyStore    <- EitherT(getKeyStore("password", keyStorePath))
      keyPair     <- EitherT(createKeyPairRSA())
      certificate <- EitherT(createSelfSignedCertificate(alias))
      _           <- EitherT(storeCertificate(keyStore, certificate, alias, "password".toArray[Char]))

      kp   <- EitherT(createKeyPair(alias))
      _    <- EitherT(storePrivateKey(keyStore, kp, alias, "password", certificate))
      root <- EitherT(createDWN(dwnUrl, s"did:key:${kp.computeThumbprint().toString()}"))
      did   = root.tenant.tenantId.dwnDidEquivalent
      kSet  = new JWKSet(kp).toPublicJWKSet().toString()
    // _    <- IO.println(s"Your DID is: $did")

    // _  <- storePublicKey(contextFilePath, alias, kp.getPublic().toString())
    yield (did, kSet)).value */

  def fetchDID(alias: String): IO[Either[Throwable, String]] =
    for
      // keyStore <- getKeyStore("password", keyStorePath)
      pk <- getPublicKey(contextFilePath, alias)

      /*   getPublicKey(contextFilePath, alias).unsafeRunSync() match
        case Some(pk) => s"did:key:$pk".asRight[Throwable][IO]
        case None     => Left(new Exception("Invalid Public Key"))[IO] */
    yield s"did:key:$pk".asRight[Throwable]

  def generateQRCode(text: String, filePath: os.Path): IO[Unit] =

    val qrCodeWriter  = new QRCodeWriter()
    val hints         = new java.util.HashMap[EncodeHintType, Any]()
    hints.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.L)
    val bitMatrix     = qrCodeWriter.encode(text, BarcodeFormat.QR_CODE, 200, 200, hints)
    val bufferedImage = new BufferedImage(200, 200, BufferedImage.TYPE_INT_RGB)
    for (x <- 0 until 200)
      for (y <- 0 until 200)
        bufferedImage.setRGB(x, y, if (bitMatrix.get(x, y)) 0xff000000 else 0xffffffff)
    for
      _ <- IO(os.makeDir.all(filePath / os.up))
      _ <- IO(ImageIO.write(bufferedImage, "png", new File(filePath.toString())))
    yield ()

  def createDWN(url: String, did: String): IO[Either[Error, Root]] = {
    val params  = s"""{"ownerDid":"$did"}"""
    val request = basicRequest
      .post(uri"$url")
      .contentType("application/json")
      .body(params)
      .response(asJson[Root])
    println(s"\nRequest DWN instance to be created:\n${request.toCurl}")
    for
      response <- AsyncHttpClientCatsBackend.resource[IO]().use(backend => backend.send(request))
      root     <- IO(response.body match
                    case Left(e)  => Left(Error(e.getMessage()))
                    case Right(b) => Right(b)
                  )
    yield root
  }
