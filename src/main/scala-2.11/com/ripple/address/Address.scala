package com.ripple.address

import com.ripple.address.Helpers.bytes

object Address {
  val b58 = BaseX(
    "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz")

  val SeedTypeEd25519 = "eddsa"
  val SeedTypeK256 = "secp256k1"

  val Address = BaseX.Version(bytes(0), expectedLength = 20)
  val Seed = BaseX.Version(bytes(33), expectedLength = 16)
  val EdSeed = BaseX.Version(bytes(0x01, 0xe1, 0x4b), expectedLength = 16)
  val AnySeed = Map(SeedTypeEd25519 -> EdSeed, SeedTypeK256 -> Seed)

  def decodeAddress(input: String) = b58.decode(input, Address)

  def encodeAddress(input: Seq[Byte]) = b58.encode(input, Address)

  def validateAddress(input: String) = b58.validate(input, Address)

  def decodeSeed(input: String) = b58.decode(input, AnySeed)

  def validateSeed(input: String) = b58.validate(input, AnySeed)

  def encodeSeed(input: Seq[Byte], name: String = SeedTypeK256) = {
    b58.encode(input, name, AnySeed)
  }
}

private object Helpers {
  def bytes(array: Int*): Array[Byte] = {
    array.map(_.toByte).toArray
  }
}
