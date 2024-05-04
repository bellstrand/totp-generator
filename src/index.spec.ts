import { TOTP, TOTPAlgorithm } from "."

describe("totp generation", () => {
	beforeEach(() => jest.useFakeTimers())
	afterEach(() => jest.resetAllMocks())

	test("should generate token with date now = 1971", () => {
		jest.setSystemTime(0)
		expect(TOTP.generate("JBSWY3DPEHPK3PXP").otp).toEqual("282760")
	})

	test("should generate token with date now = 2016", () => {
		jest.setSystemTime(1465324707000)
		expect(TOTP.generate("JBSWY3DPEHPK3PXP").otp).toEqual("341128")
	})

	test("should generate correct token at the start of the cycle", () => {
		const start = 1665644340000
		jest.setSystemTime(start + 1)
		expect(TOTP.generate("JBSWY3DPEHPK3PXP").otp).toEqual("886842")
	})

	test("should generate correct token at the end of the cycle", () => {
		const start = 1665644340000
		jest.setSystemTime(start - 1)
		expect(TOTP.generate("JBSWY3DPEHPK3PXP").otp).toEqual("134996")
	})

	test("should generate token with a leading zero", () => {
		jest.setSystemTime(1365324707000)
		expect(TOTP.generate("JBSWY3DPEHPK3PXP").otp).toEqual("089029")
	})

	test("should generate token from a padded base32 key", () => {
		jest.setSystemTime(1465324707000)
		expect(TOTP.generate("CI2FM6EQCI2FM6EQKU======").otp).toEqual("984195")
	})

	test("should throw if key contains an invalid character", () => {
		jest.setSystemTime(1465324707000)
		expect(() => TOTP.generate("JBSWY3DPEHPK3!@#")).toThrow("Invalid base32 character in key")
	})

	test("should generate longer-lasting token with date now = 2016", () => {
		jest.setSystemTime(1465324707000)
		expect(TOTP.generate("JBSWY3DPEHPK3PXP", { period: 60 }).otp).toEqual("313995")
	})

	test("should generate longer token with date now = 2016", () => {
		jest.setSystemTime(1465324707000)
		expect(TOTP.generate("JBSWY3DPEHPK3PXP", { digits: 8 }).otp).toEqual("43341128")
	})

	test("should generate SHA-512-based token with date now = 2016", () => {
		jest.setSystemTime(1465324707000)
		expect(TOTP.generate("JBSWY3DPEHPK3PXP", { algorithm: "SHA-512" }).otp).toEqual("093730")
	})

	test.each([
		{ algorithm: "SHA-1", expected: "341128" },
		{ algorithm: "SHA-224", expected: "991776" },
		{ algorithm: "SHA-256", expected: "461529" },
		{ algorithm: "SHA-384", expected: "988682" },
		{ algorithm: "SHA-512", expected: "093730" },
		{ algorithm: "SHA3-224", expected: "045085" },
		{ algorithm: "SHA3-256", expected: "255060" },
		{ algorithm: "SHA3-384", expected: "088901" },
		{ algorithm: "SHA3-512", expected: "542105" },
	] as { algorithm: TOTPAlgorithm; expected: string }[])("should generate token based on %p algorithm", ({ algorithm, expected }) => {
		jest.setSystemTime(1465324707000)
		expect(TOTP.generate("JBSWY3DPEHPK3PXP", { algorithm }).otp).toEqual(expected)
	})

	test("should generate token with timestamp from options", () => {
		expect(TOTP.generate("JBSWY3DPEHPK3PXP", { timestamp: 1465324707000 }).otp).toEqual("341128")
	})

	test("should return all values when values is less then digits", () => {
		jest.setSystemTime(1634193300000)
		expect(TOTP.generate("3IS523AYRNFUE===", { digits: 9 }).otp).toEqual("97859470")
	})

	test("should trigger leftpad fix", () => {
		jest.setSystemTime(12312354132421332222222222)
		expect(TOTP.generate("JBSWY3DPEHPK3PXP").otp).toEqual("895896")
	})

	test("should trigger leftpad fix", () => {
		jest.mock("jssha", () => ({
			__esModule: true,
			default: "mockedDefaultExport",
			namedExport: jest.fn(),
		}))
		jest.setSystemTime(12312354132421332222222222)
		expect(TOTP.generate("JBSWY3DPEHPK3PXP").otp).toEqual("895896")
	})

	test("should generate token with correct expires", () => {
		const start = 1665644340000
		jest.setSystemTime(start - 1)
		expect(TOTP.generate("JBSWY3DPEHPK3PXP")).toEqual({ otp: "134996", expires: start })
		jest.setSystemTime(start)
		expect(TOTP.generate("JBSWY3DPEHPK3PXP")).toEqual({ otp: "886842", expires: start + 30000 })
		jest.setSystemTime(start + 1)
		expect(TOTP.generate("JBSWY3DPEHPK3PXP")).toEqual({ otp: "886842", expires: start + 30000 })
		jest.setSystemTime(start + 29999)
		expect(TOTP.generate("JBSWY3DPEHPK3PXP")).toEqual({ otp: "886842", expires: start + 30000 })
		jest.setSystemTime(start + 30000)
		expect(TOTP.generate("JBSWY3DPEHPK3PXP")).toEqual({ otp: "421127", expires: start + 60000 })
		jest.setSystemTime(start + 30001)
		expect(TOTP.generate("JBSWY3DPEHPK3PXP")).toEqual({ otp: "421127", expires: start + 60000 })
	})
})
