package com.ripple.signing

import java.security.SecureRandom

import com.ripple.address.Address
import com.ripple.signing.eddsa.EdKeyPair
import com.ripple.signing.k256.K256KeyGenerator
import com.ripple.utils.Sha512

class Seed(val bytes: Array[Byte],
           var seedType: String = Address.SeedTypeK256) {

  def setEd25519(): Seed = {
    seedType = Address.SeedTypeEd25519
    this
  }

  override def toString = Address.encodeSeed(bytes, seedType)

  def keyPair(keyIndex: Int = 0): KeyPair = {
    seedType match {
      case Address.SeedTypeEd25519 =>
        EdKeyPair.from128Seed(bytes)
      case Address.SeedTypeK256 =>
        K256KeyGenerator.from128Seed(bytes, keyIndex)
    }
  }
}

object Seed {
  def fromBase58(b58: String): Seed = {
    val decoded = Address.decodeSeed(b58)
    new Seed(decoded.payload, decoded.payloadType)
  }

  def fromRandom() = {
    val seed = Array.ofDim[Byte](16)
    new SecureRandom().nextBytes(seed)
    new Seed(seed)
  }

  def fromPassPhrase(phrase: String) = new Seed(phraseToSeed(phrase))

  private def phraseToSeed(phrase: String): Array[Byte] = {
    new Sha512(phrase.getBytes("utf-8")).finish128
  }
}
