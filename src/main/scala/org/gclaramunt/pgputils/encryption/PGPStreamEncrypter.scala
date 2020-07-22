package org.gclaramunt.pgputils.encryption

import java.io._
import java.security.SecureRandom
import java.util.Date

import org.bouncycastle.bcpg.{ArmoredOutputStream, SymmetricKeyAlgorithmTags}
import org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME
import org.bouncycastle.openpgp._
import org.bouncycastle.openpgp.operator.jcajce.{JcePGPDataEncryptorBuilder, JcePublicKeyKeyEncryptionMethodGenerator}

import scala.util.Try

object PGPStreamEncrypter {

  PGPUtilities.registerBC()

  def apply(publicKey: String) = new PGPStreamEncrypter(new ByteArrayInputStream(publicKey.getBytes()))

  def apply(publicKeyInStream: InputStream) = new PGPStreamEncrypter(publicKeyInStream)
}

class PGPStreamEncrypter private(publicKeyIn: InputStream) {

  private val WORK_BUFFER_SIZE = 4096

  private val tPgpPub = PGPUtilities.publicKeyRingCollection(publicKeyIn)
  private val tEncKey = for {
    publicKeyRing <- tPgpPub
    encKey <- PGPUtilities.findPublicKey(publicKeyRing)
  } yield encKey

  def encryptStream(
                     armor: Boolean,
                     withIntegrityCheck: Boolean = false
                   )(fileName: String, dataInput: InputStream, encryptedOutStream: OutputStream) = {
    for {
      encKey <- tEncKey
      _ <- tryEncryptStream(fileName, dataInput, encryptedOutStream, encKey, armor, withIntegrityCheck)
    } yield ()

  }

  private def tryEncryptStream(
                                fileName: String,
                                in: InputStream,
                                out: OutputStream,
                                encKey: PGPPublicKey,
                                armor: Boolean,
                                withIntegrityCheck: Boolean
                              ): Try[Unit] = {
    val resultStream = if (armor) new ArmoredOutputStream(out) else out

    def newBuffer = new Array[Byte](WORK_BUFFER_SIZE)

    Try {
      val encGen = new PGPEncryptedDataGenerator(
        new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.CAST5)
          .setWithIntegrityPacket(withIntegrityCheck)
          .setSecureRandom(new SecureRandom)
          .setProvider(PROVIDER_NAME)
      )

      encGen.addMethod(
        new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider(PROVIDER_NAME)
      )
      val cOut = encGen.open(resultStream, newBuffer)

      val lData = new PGPLiteralDataGenerator
      val modifDate = new Date
      val pOut = lData.open(cOut, PGPLiteralData.BINARY, fileName, modifDate, newBuffer)

      PGPUtilities.pipeStreams(
        in,
        pOut,
        WORK_BUFFER_SIZE
      )
      cOut.close()
      pOut.close()
      resultStream.close()
    }
  }
}
