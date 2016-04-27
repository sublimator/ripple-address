package com.ripple.signing.k256

import java.math.BigInteger

import com.ripple.utils.Sha512
import org.bouncycastle.math.ec.ECPoint

import scala.None

object K256KeyGenerator {
  def from128Seed(seedBytes: Array[Byte], keyIndex: Int): K256KeyPair = {
    val privateGen = computePrivateGen(seedBytes)
    val privateKey = if (keyIndex == -1) privateGen
    else computePrivateKey(privateGen, keyIndex)
    new K256KeyPair(privateKey)
  }

  def computePrivateKey(privateGen: BigInteger, accountNumber: Int):
  BigInteger = {
    val publicGen = computePublicGenerator(privateGen)
    computeScalar(publicGen.getEncoded(true), Some(accountNumber))
      .add(privateGen).mod(K256.order)
  }

  def computePublicGenerator(privateGen: BigInteger): ECPoint = {
    computePublicKey(privateGen)
  }

  def computePrivateGen(seedBytes: Array[Byte]): BigInteger = {
    computeScalar(seedBytes, None)
  }

  def computeScalar(seedBytes: Array[Byte],
                    discriminator: Option[Int]): BigInteger = {
    // We really should loop `to` (2^32)-1 but we only ever pass a few
    // iterations here anyway at MOST
    (0 until Int.MaxValue).toStream.map(i => {
      val sha512 = new Sha512(seedBytes)
      discriminator match {
        case Some(o) => sha512.addU32(o)
        case _ =>
      }
      sha512.addU32(i)
      new BigInteger(1, sha512.finish256)
    }).find(validScalar).get
  }

  private def validScalar(key: BigInteger): Boolean = {
    key.compareTo(BigInteger.ZERO) == 1 &&
      key.compareTo(K256.order) == -1
  }

  /**
    * @param publicGenBytes - public generator point encoded in compressed form
    * @param accountNumber  - account index
    * @return public key point in compressed encoded form
    */
  def computePublicKey(publicGenBytes: Array[Byte],
                       accountNumber: Int): Array[Byte] = {
    val rootPubPoint = K256.curve.decodePoint(publicGenBytes)
    val scalar = computeScalar(publicGenBytes, Some(accountNumber))
    val point = K256.basePoint.multiply(scalar)
    val offset = rootPubPoint.add(point)
    offset.getEncoded(true)
  }

  def computePublicKey(secret: BigInteger): ECPoint = {
    K256.basePoint.multiply(secret)
  }
}
