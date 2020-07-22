package org.gclaramunt.pgputils.encryption

import java.io.{InputStream, OutputStream}
import java.security.Security

import org.bouncycastle.jce.provider.BouncyCastleProvider.{PROVIDER_NAME => BC_PROVIDER_NAME}
import org.bouncycastle.openpgp._
import org.bouncycastle.openpgp.operator.jcajce.{JcaKeyFingerprintCalculator, JcePBESecretKeyDecryptorBuilder}

import scala.collection.JavaConverters._
import scala.util.{Failure, Success, Try}

object PGPUtilities {

  /**
    * Reads a pgp secret key ring collection from an input stream
    */
  def secretKeyRingCollection(keyIn: InputStream) = Try(
    new PGPSecretKeyRingCollection(
      PGPUtil.getDecoderStream(keyIn),
      new JcaKeyFingerprintCalculator
    )
  )

  /**
    * Reads a pgp public key ring collection from an input stream
    */
  def publicKeyRingCollection(keyIn: InputStream) = Try(
    new PGPPublicKeyRingCollection(
      PGPUtil.getDecoderStream(keyIn),
      new JcaKeyFingerprintCalculator
    )
  )

  /**
    * Search a secret key ring collection for a secret key corresponding to keyID if it
    * exists.
    */
  def findSecretKey(pgpSec: PGPSecretKeyRingCollection, keyID: Long, pass: Array[Char]): Try[PGPPrivateKey] =
    for {
      pgpSecKey <- Try(pgpSec.getSecretKey(keyID)) if pgpSecKey != null
      secKey <- Try(
        pgpSecKey.extractPrivateKey(
          new JcePBESecretKeyDecryptorBuilder().setProvider(BC_PROVIDER_NAME).build(pass)
        )
      )
    } yield secKey

  /**
    * Search a public key ring collection for the first available public encryption key
    */
  def findPublicKey(pgpPub: PGPPublicKeyRingCollection): Try[PGPPublicKey] = {
    val pubKeys = for {
      keyRing <- pgpPub.getKeyRings.asScala
      pubKey <- keyRing.getPublicKeys.asScala
      if pubKey.isEncryptionKey
    } yield pubKey
    toTry(pubKeys.toList.headOption, "No encryption public key found")
  }

  def toTry[T](o: Option[T], noneMessage: String): Try[T] =
    o.fold[Try[T]](Failure(new PGPException(noneMessage)))(Success(_))

  /**
    * Registers Bouncy Castle as Java security provider
    */
  def registerBC(): Unit = {
    if (Security.getProvider(BC_PROVIDER_NAME) == null)
      Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider())
    ()
  }

  /**
    * Pipes an input stream into an output stream using a buffer of specified size
    */
  def pipeStreams(in: InputStream, pOut: OutputStream, bufSize: Int) = {
    val buf: Array[Byte] = new Array[Byte](bufSize)
    var len: Int = 0
    while ( {
      len = in.read(buf)
      len > 0
    }) {
      pOut.write(buf, 0, len)
    }
    pOut.close()
  }
}
