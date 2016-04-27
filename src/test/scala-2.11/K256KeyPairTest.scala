import java.security.Security

import com.ripple.signing.Seed
import com.ripple.signing.k256.K256KeyPair
import com.ripple.utils.B16
import org.scalatest.FunSpec

import scala.io.Source

class K256KeyPairTest extends FunSpec {
  describe("secp256k1 signing") {
    val stream = getClass.getResourceAsStream("secp256k1-sigs.txt")
    val lines = Source.fromInputStream(stream).getLines.toList
    val pair = Seed.fromPassPhrase("niq") // cast to get access to:
                   .keyPair().asInstanceOf[K256KeyPair]
    val pairPrivate = pair.privateKey.toString(16).toUpperCase
    val pairPublic = B16.encode(pair.pubKeyCanonical)

    it("generated the correct private key") {
      val expectedPrivate =
        "152E883D92D57814CC0B4E00C1449F153BF59965C78F5ADE7E0B15B3EDE3915C"
      assertResult(expectedPrivate)(pairPrivate)
    }

    it("generated the correct public key") {
      val expectedPublic =
        "021E788CDEB9104C9179C3869250A89999C1AFF92D2C3FF7925A1696835EA3D840"
      assertResult(expectedPublic)(pairPublic)
    }

    (0 until 16).foreach(i => {
      val msg = Array(i.toByte)
      it(s"signing ${B16.encode(msg)}") {
        val sigBytes = pair.sign(msg)
        val sig = B16.encode(sigBytes)
        assert(pair.verify(msg, sigBytes))
        assertResult(lines(i))(sig)
      }
    })
  }
}