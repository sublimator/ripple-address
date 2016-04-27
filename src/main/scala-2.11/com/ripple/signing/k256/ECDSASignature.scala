package com.ripple.signing.k256

import java.io.ByteArrayOutputStream
import java.math.BigInteger

import org.bouncycastle.asn1.{ASN1InputStream, ASN1Integer, DERSequenceGenerator, DLSequence}

object ECDSASignature {
  def isStrictlyCanonical(sig: Array[Byte]): Boolean = {
    checkIsCanonical(sig, strict = true)
  }

  def checkIsCanonical(sig: Array[Byte], strict: Boolean): Boolean = {
    val sigLen: Int = sig.length
    if ((sigLen < 8) || (sigLen > 72)) return false
    if ((sig(0) != 0x30) || (sig(1) != (sigLen - 2))) return false
    val rPos: Int = 4
    val rLen: Int = sig(rPos - 1)
    if ((rLen < 1) || (rLen > 33) || ((rLen + 7) > sigLen)) return false
    val sPos: Int = rLen + 6
    val sLen: Int = sig(sPos - 1)
    if ((sLen < 1) || (sLen > 33) || ((rLen + sLen + 6) != sigLen)) return false
    if ((sig(rPos - 2) != 0x02) || (sig(sPos - 2) != 0x02)) return false
    if ((sig(rPos) & 0x80) != 0) return false
    if ((sig(rPos) == 0) && rLen == 1) return false
    if ((sig(rPos) == 0) && ((sig(rPos + 1) & 0x80) == 0)) return false
    if ((sig(sPos) & 0x80) != 0) return false
    if ((sig(sPos) == 0) && sLen == 1) return false
    if ((sig(sPos) == 0) && ((sig(sPos + 1) & 0x80) == 0)) return false
    val rBytes: Array[Byte] = new Array[Byte](rLen)
    val sBytes: Array[Byte] = new Array[Byte](sLen)
    System.arraycopy(sig, rPos, rBytes, 0, rLen)
    System.arraycopy(sig, sPos, sBytes, 0, sLen)
    val r: BigInteger = new BigInteger(1, rBytes)
    val s: BigInteger = new BigInteger(1, sBytes)
    val order: BigInteger = K256.order
    if (r.compareTo(order) != -1 || s.compareTo(order) != -1) {
      return false
    }
    if (strict) {
      order.subtract(s).compareTo(s) != -1
    }
    else {
      true
    }
  }

  def decodeFromDER(bytes: Array[Byte]): ECDSASignature = {
    val decoder = new ASN1InputStream(bytes)
    val seq = decoder.readObject.asInstanceOf[DLSequence]
    var r: ASN1Integer = null
    var s: ASN1Integer = null

    try {
      r = seq.getObjectAt(0).asInstanceOf[ASN1Integer]
      s = seq.getObjectAt(1).asInstanceOf[ASN1Integer]
    }
    finally {
      decoder.close()
    }
    new ECDSASignature(r.getPositiveValue, s.getPositiveValue)
  }
}

class ECDSASignature(val r: BigInteger, val s: BigInteger) {
  def encodeToDER: Array[Byte] = derByteStream.toByteArray

  private def derByteStream: ByteArrayOutputStream = {
    val bos = new ByteArrayOutputStream(72)
    val seq = new DERSequenceGenerator(bos)
    seq.addObject(new ASN1Integer(r))
    seq.addObject(new ASN1Integer(s))
    seq.close()
    bos
  }
}