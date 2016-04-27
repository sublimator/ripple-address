package com.ripple.signing.k256

import com.ripple.signing.VerifyingKey
import com.ripple.utils.HashUtils
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.math.ec.ECPoint

class K256VerifyingKey(val publicKey: ECPoint) extends VerifyingKey {
  private val verifySigner = {
    val signer = new ECDSASigner
    val params = new ECPublicKeyParameters(publicKey, K256.params)
    signer.init(false, params)
    signer
  }

  override def pubKeyCanonical = publicKey.getEncoded(true)

  override def verify(message: Array[Byte], signature: Array[Byte]): Boolean = {
    val hash = HashUtils.halfSha512(message)
    val der = ECDSASignature.decodeFromDER(signature)
    verifySigner.verifySignature(hash, der.r, der.s)
  }
}
