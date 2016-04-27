package com.ripple.signing.k256

import java.math.BigInteger

import com.ripple.signing.KeyPair
import com.ripple.utils.HashUtils
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.signers.{ECDSASigner, HMacDSAKCalculator}

class K256KeyPair(val privateKey: BigInteger) extends
  K256VerifyingKey(K256KeyGenerator.computePublicKey(privateKey)) with KeyPair {
  val signer = {
    val signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()))
    val params = new ECPrivateKeyParameters(privateKey, K256.params)
    signer.init(true, params)
    signer
  }

  override def sign(message: Array[Byte]): Array[Byte] = {
    val hash = HashUtils.halfSha512(message)
    var Array(r, s) = signer.generateSignature(hash)
    val otherS = K256.order.subtract(s)
    if (s.compareTo(otherS) == 1) s = otherS
    val bytes = new ECDSASignature(r, s).encodeToDER
    assert(ECDSASignature.isStrictlyCanonical(bytes))
    bytes
  }
}
