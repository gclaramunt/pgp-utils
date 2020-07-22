package org.gclaramunt.pgputils.encryption

import java.io._

import org.scalatest.{FreeSpec, Matchers}

class PGPStreamEncrypterTest extends FreeSpec with Matchers {

  def bufferedStreamFromFile(path: String) =
    new BufferedInputStream(new FileInputStream(new File(path)))

  "test encrypt stream" - {

    "successful encrypt stream" in {

      val bobPrivateKeys = bufferedStreamFromFile("src/test/resources/keys/bobsecring.asc")
      val publicKeys = bufferedStreamFromFile("src/test/resources/keys/bobpubring.asc")

      val plain = bufferedStreamFromFile("src/test/resources/el-quijote.txt")
      val expected = scala.io.Source.fromFile("src/test/resources/el-quijote.txt")

      val baseOut = new ByteArrayOutputStream()

      val result =
        PGPStreamEncrypter(publicKeys).encryptStream(armor = false)(
          "target.txt",
          plain,
          new BufferedOutputStream(baseOut)
        )

      baseOut.close()

      val password = "bobkey123".toCharArray

      result shouldBe 'success

      val (content, fileName) = decrypt(bobPrivateKeys, password, baseOut.toByteArray)
      content shouldBe expected.mkString
      fileName shouldBe "target.txt"

    }
  }

  private def decrypt(secretKeys: InputStream, password: Array[Char], data: Array[Byte]) = {
    val encrypted = new ByteArrayInputStream(data)
    val (decrypted, fileName) = PGPStreamDecrypter(secretKeys, password).decryptStream(encrypted).get
    (scala.io.Source.fromInputStream(decrypted).mkString, fileName)
  }

}
