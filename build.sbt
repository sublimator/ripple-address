name := "ripple-address"

version := "1.0"

scalaVersion := "2.11.8"

libraryDependencies += "org.bouncycastle" % "bcprov-jdk15on" % "1.52" %
  "compile"

libraryDependencies += "org.scalatest" %% "scalatest" % "2.2.6" % "test"

libraryDependencies += "com.github.emstlk" %% "nacl4s" % "1.0.0"