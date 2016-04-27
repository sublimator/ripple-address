import com.ripple.signing.Seed
import org.scalatest.FunSpec

class SeedTest extends FunSpec {
  describe("secp256k1 key generation") {
    it("can generate the root account") {
      val rootSeed = "snoPBrXtMeMyMHUVTgbuqAfg1SUTb"
      val rootAddress = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
      val derived = Seed.fromBase58(rootSeed).keyPair().id
      val rootSeedFromPhrase = Seed.fromPassPhrase("masterpassphrase").toString
      assertResult(rootAddress)(derived)
      assertResult(rootSeed)(rootSeedFromPhrase)
    }
    it("can generate the niq account") {
      val niqSeed = "shQUG1pmPYrcnSUGeuJFJTA1b3JSL"
      val niqAddress = "rNvfq2SVbCiio1zkN5WwLQW8CHgy2dUoQi"
      val derived = Seed.fromBase58(niqSeed).keyPair().id
      val niqSeedFromPhrase = Seed.fromPassPhrase("niq").toString
      assertResult(niqAddress)(derived)
      assertResult(niqSeed)(niqSeedFromPhrase)
    }
  }
  describe("ed25519 key generation") {
    it("can generate the niq account") {
      val niqSeed = "sEd7rBGm5kxzauRTAV2hbsNz7N45X91"
      val niqAddress = "rJZdUusLDtY9NEsGea7ijqhVrXv98rYBYN"
      val derived = Seed.fromBase58(niqSeed).keyPair().id
      val niqSeedFromPhrase = Seed.fromPassPhrase("niq")
                                  .setEd25519().toString
      assertResult(niqAddress)(derived)
      assertResult(niqSeed)(niqSeedFromPhrase)
    }
  }
}
