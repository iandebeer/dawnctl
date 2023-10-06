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
import java.security.PublicKey

object DIDOps:
  def makeDidKey(pubKey: PublicKey, kty: String, crv: String): Option[String] =
    val algo = (kty, crv) match
      case ("EC", "P-256") => "zDn"
      case ("EC", "P-384") => "z82"
      case ("EC", "P-521") => "z2J9"
      case _               => ""
    val key  = pubKey.getEncoded() match
      case x: Array[Byte] => Some(encodeToBase58(x))
      case null           => None
    (algo, key) match
      case (a, Some(k)) => Some(s"did:key:$a$k")
      case _            => None

  val alphabetBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

  val idxToChar = Map(alphabetBase58.zipWithIndex.map(_.swap): _*)

  val charToIdx = Map(alphabetBase58.zipWithIndex: _*)

  def encodeToBase58(array: Array[Byte]): String =
    (LazyList.fill(array.takeWhile(_ == 0).length)(1.toByte) ++ LazyList
      .unfold(
        BigInt(0.toByte +: array)
      )(n => if (n == 0) None else Some((n /% 58).swap))
      .map(_.toInt)
      .reverse
      .map(x => idxToChar(x))).mkString

  def decodeFromBase58(b58: String): Array[Byte] = {
    val zeroCount = b58.takeWhile(_ == '1').length
    Array.fill(zeroCount)(0.toByte) ++
      b58
        .drop(zeroCount)
        .map(charToIdx)
        .toList
        .foldLeft(BigInt(0))((acc, x) => acc * 58 + x)
        .toByteArray
        .dropWhile(_ == 0.toByte)
  }

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
