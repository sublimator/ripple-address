package com.ripple.utils

import org.bouncycastle.crypto.digests.{GeneralDigest, RIPEMD160Digest, SHA256Digest}

object HashUtils {
  def halfSha512(input: Array[Byte]) = new Sha512(input).finish256

  def ripe160ofSha256(input: Array[Byte]): Array[Byte] = {
    doDigest(doDigest(input, new SHA256Digest), new RIPEMD160Digest)
  }

  private def doDigest(sha256: Array[Byte], digest: GeneralDigest) = {
    digest.update(sha256, 0, sha256.length)
    val out = Array.ofDim[Byte](digest.getDigestSize)
    digest.doFinal(out, 0)
    out
  }
}
