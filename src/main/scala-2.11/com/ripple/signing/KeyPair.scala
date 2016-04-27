package com.ripple.signing

trait KeyPair extends VerifyingKey {
  def sign(message: Array[Byte]): Array[Byte]
}
