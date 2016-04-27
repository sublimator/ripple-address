package com.ripple.signing

import com.ripple.address.Address
import com.ripple.signing.k256.{K256, K256VerifyingKey}
import com.ripple.utils.HashUtils

trait VerifyingKey {
  def pubKeyCanonical: Array[Byte]

  def verify(message: Array[Byte], signature: Array[Byte]): Boolean

  def pub160Hash = HashUtils.ripe160ofSha256(pubKeyCanonical)

  def id = Address.encodeAddress(pub160Hash)
}

object VerifyingKey {
  def fromPubKeyCanonical(pubKey: Array[Byte]): VerifyingKey = {
    new K256VerifyingKey(K256.curve.decodePoint(pubKey))
  }
}
