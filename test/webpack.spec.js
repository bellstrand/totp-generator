"use strict"

jest.mock("jssha", () => ({
	__esModule: true,
	default: class Test {
		setHMACKey() {}
		update() {}
		getHMAC() {
			return "2cd8e904e395a7414877aa2f8261e1243572c435"
		}
	},
}))

let totp = require("../index")

describe("webpack", () => {
	it("should fix webpack default require", () => {
		global.Date.now = () => 0
		expect(totp("JBSWY3DPEHPK3PXP")).toEqual("282760")
	})
})
