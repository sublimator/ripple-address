class BaseXTest extends org.scalatest.FunSpec {
  def makeTest(name: String): Unit = {
    describe("something" + name) {
      it("can do stuff") {

      }
    }
  }
}
