package com.ripple.signing.eddsa

import com.emstlk.nacl4s.crypto.{SigningKey, SigningKeyPair, VerifyKey}
import com.ripple.signing.{KeyPair, VerifyingKey}
import com.ripple.utils.HashUtils

class EdVerifyingKey(pubKey: Array[Byte]) extends VerifyingKey {
  private val verifyKey = new VerifyKey(pubKey)
  private val _pubKeyCanonical = Array(0xED.toByte) ++ pubKey
  override def pubKeyCanonical = _pubKeyCanonical
  override def verify(message: Array[Byte], signature: Array[Byte]) = {
    try {
      verifyKey.verify(message, signature)
      true
    } catch {
      case illegal: IllegalArgumentException =>
        false
    }
  }
}

class EdKeyPair(val privateKey: Array[Byte], pubKey: Array[Byte])
  extends EdVerifyingKey(pubKey) with KeyPair {
  private val signingKey = SigningKey(privateKey)
  override def sign(message: Array[Byte]) = signingKey.sign(message)
}

object EdKeyPair {
  def from128Seed(seed: Array[Byte]): EdKeyPair = {
    val sha = HashUtils.halfSha512(seed)
    val pair = SigningKeyPair(sha)
    val SigningKeyPair(priv, pub) = pair
    new EdKeyPair(priv, pub)
  }
}
