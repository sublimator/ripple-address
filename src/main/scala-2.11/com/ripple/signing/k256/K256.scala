package com.ripple.signing.k256

import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.crypto.params.ECDomainParameters

object K256 {
  private val x9Params = SECNamedCurves.getByName("secp256k1")
  val params = new ECDomainParameters(
    x9Params.getCurve, x9Params.getG, x9Params.getN, x9Params.getH)

  def order = params.getN

  def curve = params.getCurve

  def basePoint = params.getG
}
