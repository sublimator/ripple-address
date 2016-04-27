package com.ripple.address

import java.math.BigInteger
import java.security.MessageDigest

import com.ripple.address.BaseX._

import scala.annotation.tailrec

class BaseX(val alphabet: String) {
  val base: Long = alphabet.length
  val reverse = alphabet.zipWithIndex
    .map(e => (e._1, BigInteger.valueOf(e._2)))
    .toMap
  val leader = alphabet.charAt(0)
  var baseBigInt = BigInteger.valueOf(base)

  def rawEncode(input: Seq[Byte]): String = {
    if (input.isEmpty) ""
    else {
      val big = new BigInteger(1, input.toArray)
      val builder = new StringBuilder

      @tailrec
      def inner(current: BigInteger): Unit = current match {
        case BigInteger.ZERO =>
        case _ =>
          val Array(x, remainder) = current.divideAndRemainder(baseBigInt)
          val at = alphabet.charAt(remainder.intValue)
          builder.append(at)
          inner(x)
      }
      inner(big)
      input.takeWhile(_ == 0).map(_ => builder.append(leader))
      builder.toString().reverse
    }
  }

  def rawDecode(input: String): Array[Byte] = {
    val zeroes = input.takeWhile(_ == leader).map(_ => 0: Byte).toArray
    val trim = input.dropWhile(_ == leader).toList
    if (trim.isEmpty)
      zeroes
    else {
      val decoded = trim.foldLeft(BigInteger.ZERO)(
        (a, b) => a.multiply(baseBigInt).add(reverse(b)))
      // BigInteger.toByteArray may add a leading 0x00
      zeroes ++ decoded.toByteArray.dropWhile(_ == 0)
    }
  }

  def encode(payload: Seq[Byte], version: Version): String = {
    if (version.expectedLength != payload.length)
      throw new PayloadLengthError
    val joined = version.versionBytes ++ payload
    val check = checkSum(joined)
    rawEncode(joined ++ check)
  }

  def encode(payload: Seq[Byte], payloadType: String,
             versions: Map[String, Version]): String = {
    if (!versions.contains(payloadType)) {
      throw new VersionError
    }
    encode(payload, versions(payloadType))
  }

  def decode(encoded: String, version: Version) = {
    val slice = removeChecksum(encoded)
    if (!checkVersion(slice, version))
      throw new VersionError
    extractPayload(slice, version)
  }

  def decode(encoded: String, versions: Map[String, Version]): Decoding = {
    val slice = removeChecksum(encoded)
    val check = versions.find(t => checkVersion(slice, t._2))
    if (check.isEmpty)
      throw new VersionError

    val (name, foundVersion) = check.get
    Decoding(name, foundVersion, extractPayload(slice, foundVersion))
  }

  def validate(encoded: String, version: Version) = {
    throwsBaseXError(() => decode(encoded, version))
  }
  def validate(encoded: String, versions: Map[String, Version]) = {
    throwsBaseXError(() => decode(encoded, versions))
  }

  private def extractPayload(slice: Array[Byte],
                             foundVersion: Version): Array[Byte] = {
    slice.slice(foundVersion.versionBytes.length, slice.length)
  }

  private def removeChecksum(encoded: String): Array[Byte] = {
    val bytes = rawDecode(encoded)
    val checksum = bytes.slice(bytes.length - 4, bytes.length)
    val slice = bytes.slice(0, bytes.length - 4)
    val recalculated = checkSum(slice)
    if (!recalculated.sameElements(checksum)) {
      throw new ChecksumError
    }
    slice
  }

  private def checkVersion(slice: Array[Byte], version: Version): Boolean = {
    val ver = version.versionBytes
    val totalLength = version.expectedLength + ver.length
    slice.length == totalLength &&
      slice.slice(0, ver.length)
        .sameElements(ver)
  }
}

object BaseX {

  class BaseXError extends RuntimeException

  class ChecksumError extends BaseXError

  class VersionError extends BaseXError

  class PayloadLengthError extends BaseXError

  private def throwsBaseXError(fun: => Unit ): Boolean = {
    try {
      try {
        fun
        true
      } catch {
        case e: BaseXError =>
          false
      }
    }
  }

  object Version {
    def apply(version: Array[Byte], expectedLength: Int):
    Version = new Version(version, expectedLength)
  }

  object Decoding {
    def apply(payloadType: String, version: Version, payload: Array[Byte]):
    Decoding = {
      new Decoding(payloadType, version, payload)
    }
  }

  class Version(val versionBytes: Array[Byte],
                val expectedLength: Int) {
  }

  class Decoding(val payloadType: String, val version: Version, val payload:
  Array[Byte])

  private def checkSum(slice: Array[Byte]): Array[Byte] = {
    sha256x2(slice).take(4)
  }

  private def sha256x2(bytes: Seq[Byte]): Array[Byte] = {
    sha256(sha256(bytes))
  }

  private def sha256(bytes: Seq[Byte]): Array[Byte] = {
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update(bytes.toArray)
    digest.digest
  }

  def apply(alphabet: String): BaseX = new BaseX(alphabet)
}
