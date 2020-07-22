package org.gclaramunt.pgputils.encryption


import java.io.{BufferedInputStream, File, FileInputStream}

import org.scalatest.{FreeSpec, Matchers}

class PGPStreamDecrypterTest extends FreeSpec with Matchers {

  def bufferedStreamFromFile(path: String) =
    new BufferedInputStream(new FileInputStream(new File(path)))

  "testDecryptStream" - {

    "successful decrypt stream" in {

      // assume content is PGP encrypted with integration-gateway key
      val keyfile = bufferedStreamFromFile("src/test/resources/keys/secring.asc")

      val encrypted = bufferedStreamFromFile("src/test/resources/el-quijote.txt.gpg")
      val expected = scala.io.Source.fromFile("src/test/resources/el-quijote.txt").mkString

      val password = "scalents123".toCharArray

      val (result, fileName) = PGPStreamDecrypter(keyfile, password).decryptStream(encrypted).get

      val fullText = scala.io.Source.fromInputStream(result).mkString

      fileName shouldBe "el-quijote.txt"
      fullText.length shouldBe expected.length
      fullText shouldBe expected

    }

    "invalid password should fail" in {

      val keyfile = bufferedStreamFromFile("src/test/resources/keys/secring.asc")

      val encrypted = bufferedStreamFromFile("src/test/resources/el-quijote.txt.gpg")

      val password = "somegibberish".toCharArray

      val result = PGPStreamDecrypter(keyfile, password).decryptStream(encrypted)

      result shouldBe 'failure
    }

    "non recipient key should fail" in {
      val keyfile = bufferedStreamFromFile("src/test/resources/keys/bobsecring.asc")

      val encrypted = bufferedStreamFromFile("src/test/resources/el-quijote.txt.gpg")

      val password = "bobkey123".toCharArray

      val result = PGPStreamDecrypter(keyfile, password).decryptStream(encrypted)

      result shouldBe 'failure
    }

  }

}
