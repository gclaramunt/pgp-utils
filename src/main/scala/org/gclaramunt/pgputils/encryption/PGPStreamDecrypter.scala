package org.gclaramunt.pgputils.encryption

import java.io._

import org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME
import org.bouncycastle.openpgp._
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder

import scala.collection.JavaConverters._
import scala.util.{Failure, Success, Try}

object PGPStreamDecrypter {

  PGPUtilities.registerBC()

  def apply(keyIn: String, passphrase: Array[Char]) =
    new PGPStreamDecrypter(new ByteArrayInputStream(keyIn.getBytes), passphrase)

  def apply(keyIn: InputStream, passphrase: Array[Char]) = new PGPStreamDecrypter(keyIn, passphrase)
}

class PGPStreamDecrypter private(keyIn: InputStream, passphrase: Array[Char]) {

  private val tPgpSec = PGPUtilities.secretKeyRingCollection(keyIn)

  // see org.bouncycastle.openpgp.examples.KeyBasedFileProcessor
  def decryptStream(in: InputStream): Try[(InputStream, String)] = {

    // look for the first PGPEncryptedDataList packet
    val tEnc = for {
      decoderStream <- Try(PGPUtil.getDecoderStream(in)) //may throw IO Exception
      pgpF = new JcaPGPObjectFactory(decoderStream)
      enc <- getFirst { case dl: PGPEncryptedDataList => dl }(pgpF.iterator())
    } yield enc

    def extractData(is: InputStream) =
      for {
        fact <- Try(new JcaPGPObjectFactory(is))
        data <- Try(fact.nextObject()) //may throw IO Exception
      } yield data

    val tMessage = for {
      enc <- tEnc
      pbe <- getFirst { case pbe: PGPPublicKeyEncryptedData => pbe }(enc.getEncryptedDataObjects)
      pgpSec <- tPgpSec
      sKey <- PGPUtilities.findSecretKey(pgpSec, pbe.getKeyID, passphrase).recover {
        case t => throw new PGPException(s"Invalid or missing private key, error ${t.getMessage}")
      }
      clearStream <- Try(
        pbe.getDataStream(
          new JcePublicKeyDataDecryptorFactoryBuilder() //may throw PGP Exception
            .setProvider(PROVIDER_NAME)
            .build(sKey)
        )
      )
      data <- extractData(clearStream)
      cData <- data match {
        case cData: PGPCompressedData => Try(cData.getDataStream).flatMap(extractData)
        case m => Success(m)
      }
    } yield cData

    tMessage.flatMap {
      case ld: PGPLiteralData =>
        Success((ld.getInputStream, ld.getFileName))

      case _: PGPOnePassSignatureList =>
        Failure(new PGPException("encrypted message contains a signed message - not literal data."))
      case x =>
        Failure(new PGPException(s"message is not a simple encrypted file - type unknown $x."))
    }

  }

  private def getFirst[T](pf: PartialFunction[Any, T])(col: java.util.Iterator[_]): Try[T] =
    PGPUtilities.toTry(col.asScala.collectFirst(pf), "Unexpected PGP packet found")

}
