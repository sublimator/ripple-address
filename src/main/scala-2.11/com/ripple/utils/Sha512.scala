package com.ripple.utils

import java.security.MessageDigest

class Sha512 {
  val messageDigest = MessageDigest.getInstance("SHA-512")

  def this(start: Array[Byte]) {
    this
    add(start)
  }

  def add(bytes: Array[Byte]): Sha512 = {
    messageDigest.update(bytes)
    this
  }

  def addU32(i: Int): Sha512 = {
    messageDigest.update(((i >>> 24) & 0xFF).toByte)
    messageDigest.update(((i >>> 16) & 0xFF).toByte)
    messageDigest.update(((i >>> 8) & 0xFF).toByte)
    messageDigest.update((i & 0xFF).toByte)
    this
  }

  private def finishTaking(size: Int): Array[Byte] = {
    val hash = Array.ofDim[Byte](size)
    System.arraycopy(messageDigest.digest, 0, hash, 0, size)
    hash
  }

  def finish128: Array[Byte] = {
    finishTaking(16)
  }

  def finish256: Array[Byte] = {
    finishTaking(32)
  }

  def finish: Array[Byte] = {
    messageDigest.digest
  }
}