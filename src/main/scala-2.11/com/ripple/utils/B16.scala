package com.ripple.utils

import org.bouncycastle.util.encoders.Hex

object B16 {
  def encode(bytes: Array[Byte]) = Hex.toHexString(bytes).toUpperCase

  def decode(hex: String) = Hex.decode(hex)
}
