"use strict"

let totp = require("../index")

describe("totp generation", () => {
	it("should generate token with date now = 1971", () => {
		global.Date.now = () => 0
		expect(totp("JBSWY3DPEHPK3PXP")).toEqual("282760")
	})

	it("should generate token with date now = 2016", () => {
		global.Date.now = () => 1465324707000
		expect(totp("JBSWY3DPEHPK3PXP")).toEqual("341128")
	})

	it("should generate correct token at the start of the cycle", () => {
		global.Date.now = () => 1665644340100
		expect(totp("JBSWY3DPEHPK3PXP")).toEqual("886842")
	})

	it("should generate correct token at the end of the cycle", () => {
		global.Date.now = () => 1665644339900
		expect(totp("JBSWY3DPEHPK3PXP")).toEqual("134996")
	})

	it("should generate token with a leading zero", () => {
		global.Date.now = () => 1365324707000
		expect(totp("JBSWY3DPEHPK3PXP")).toEqual("089029")
	})

	it("should generate token from a padded base32 key", () => {
		global.Date.now = () => 1465324707000
		expect(totp("CI2FM6EQCI2FM6EQKU======")).toEqual("984195")
	})

	it("should throw if key contains an invalid character", () => {
		global.Date.now = () => 1465324707000
		expect(() => totp("JBSWY3DPEHPK3!@#")).toThrow("Invalid base32 character in key")
	})

	it("should generate longer-lasting token with date now = 2016", () => {
		global.Date.now = () => 1465324707000
		expect(totp("JBSWY3DPEHPK3PXP", { period: 60 })).toEqual("313995")
	})

	it("should generate longer token with date now = 2016", () => {
		global.Date.now = () => 1465324707000
		expect(totp("JBSWY3DPEHPK3PXP", { digits: 8 })).toEqual("43341128")
	})

	it("should generate SHA-512-based token with date now = 2016", () => {
		global.Date.now = () => 1465324707000
		expect(totp("JBSWY3DPEHPK3PXP", { algorithm: "SHA-512" })).toEqual("093730")
	})

	it("should generate token with timestamp from options", () => {
		expect(totp("JBSWY3DPEHPK3PXP", { timestamp: 1465324707000 })).toEqual("341128")
	})

	it("should return all values when values is less then digits", () => {
		global.Date.now = () => 1634193300000
		expect(totp("3IS523AYRNFUE===", { digits: 9 })).toEqual("97859470")
	})

	it("should trigger leftpad fix", () => {
		global.Date.now = () => 12312354132421332222222222
		expect(totp("JBSWY3DPEHPK3PXP")).toEqual("895896")
	})

	it("should trigger leftpad fix", () => {
		jest.mock("jssha", () => ({
			__esModule: true,
			default: "mockedDefaultExport",
			namedExport: jest.fn(),
		}))
		global.Date.now = () => 12312354132421332222222222
		expect(totp("JBSWY3DPEHPK3PXP")).toEqual("895896")
	})
})
