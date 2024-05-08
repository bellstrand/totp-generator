import { TOTP, TOTPAlgorithm } from "."

describe("totp generation", () => {
	beforeEach(() => jest.useFakeTimers())
	afterEach(() => jest.resetAllMocks())

	test("should generate token with date now = 1971", async () => {
		jest.setSystemTime(0)
		await expect(TOTP.generate("JBSWY3DPEHPK3PXP")).resolves.toEqual(expect.objectContaining({ otp: "282760" }))
	})

	test("should generate token with date now = 2016", async () => {
		jest.setSystemTime(1465324707000)
		await expect(TOTP.generate("JBSWY3DPEHPK3PXP")).resolves.toEqual(expect.objectContaining({ otp: "341128" }))
	})

	test("should generate correct token at the start of the cycle", async () => {
		const start = 1665644340000
		jest.setSystemTime(start + 1)
		await expect(TOTP.generate("JBSWY3DPEHPK3PXP")).resolves.toEqual(expect.objectContaining({ otp: "886842" }))
	})

	test("should generate correct token at the end of the cycle", async () => {
		const start = 1665644340000
		jest.setSystemTime(start - 1)
		await expect(TOTP.generate("JBSWY3DPEHPK3PXP")).resolves.toEqual(expect.objectContaining({ otp: "134996" }))
	})

	test("should generate token with a leading zero", async () => {
		jest.setSystemTime(1365324707000)
		await expect(TOTP.generate("JBSWY3DPEHPK3PXP")).resolves.toEqual(expect.objectContaining({ otp: "089029" }))
	})

	test("should generate token from a padded base32 key", async () => {
		jest.setSystemTime(1465324707000)
		await expect(TOTP.generate("CI2FM6EQCI2FM6EQKU======")).resolves.toEqual(expect.objectContaining({ otp: "984195" }))
	})

	test("should throw if key contains an invalid character", async () => {
		await expect(TOTP.generate("ABSWY3DPEHPK3!@#")).rejects.toThrow("Invalid base32 character in key")
	})

	test("should generate longer-lasting token with date now = 2016", async () => {
		jest.setSystemTime(1465324707000)
		await expect(TOTP.generate("JBSWY3DPEHPK3PXP", { period: 60 })).resolves.toEqual(expect.objectContaining({ otp: "313995" }))
	})

	test("should generate longer token with date now = 2016", async () => {
		jest.setSystemTime(1465324707000)
		await expect(TOTP.generate("JBSWY3DPEHPK3PXP", { digits: 8 })).resolves.toEqual(expect.objectContaining({ otp: "43341128" }))
	})

	test("should generate SHA-512-based token with date now = 2016", async () => {
		jest.setSystemTime(1465324707000)
		await expect(TOTP.generate("JBSWY3DPEHPK3PXP", { algorithm: "SHA-512" })).resolves.toEqual(expect.objectContaining({ otp: "093730" }))
	})

	test.each([
		{ algorithm: "SHA-1", expected: "341128" },
		{ algorithm: "SHA-256", expected: "461529" },
		{ algorithm: "SHA-384", expected: "988682" },
		{ algorithm: "SHA-512", expected: "093730" },
	] as { algorithm: TOTPAlgorithm; expected: string }[])("should generate token based on %p algorithm", async ({ algorithm, expected }) => {
		jest.setSystemTime(1465324707000)
		await expect(TOTP.generate("JBSWY3DPEHPK3PXP", { algorithm })).resolves.toEqual(expect.objectContaining({ otp: expected }))
	})

	test("should generate token with timestamp from options", async () => {
		await expect(TOTP.generate("JBSWY3DPEHPK3PXP", { timestamp: 1465324707000 })).resolves.toEqual(expect.objectContaining({ otp: "341128" }))
	})

	test("should return all values when values is less then digits", async () => {
		jest.setSystemTime(1634193300000)
		await expect(TOTP.generate("3IS523AYRNFUE===", { digits: 9 })).resolves.toEqual(expect.objectContaining({ otp: "97859470" }))
	})

	test("should trigger leftpad fix", async () => {
		jest.setSystemTime(12312354132421332222222222)
		await expect(TOTP.generate("JBSWY3DPEHPK3PXP")).resolves.toEqual(expect.objectContaining({ otp: "895896" }))
	})

	test("should generate token with correct expires", async () => {
		const start = 1665644340000
		jest.setSystemTime(start - 1)
		await expect(TOTP.generate("JBSWY3DPEHPK3PXP")).resolves.toEqual({ otp: "134996", expires: start })
		jest.setSystemTime(start)
		await expect(TOTP.generate("JBSWY3DPEHPK3PXP")).resolves.toEqual({ otp: "886842", expires: start + 30000 })
		jest.setSystemTime(start + 1)
		await expect(TOTP.generate("JBSWY3DPEHPK3PXP")).resolves.toEqual({ otp: "886842", expires: start + 30000 })
		jest.setSystemTime(start + 29999)
		await expect(TOTP.generate("JBSWY3DPEHPK3PXP")).resolves.toEqual({ otp: "886842", expires: start + 30000 })
		jest.setSystemTime(start + 30000)
		await expect(TOTP.generate("JBSWY3DPEHPK3PXP")).resolves.toEqual({ otp: "421127", expires: start + 60000 })
		jest.setSystemTime(start + 30001)
		await expect(TOTP.generate("JBSWY3DPEHPK3PXP")).resolves.toEqual({ otp: "421127", expires: start + 60000 })
	})

	test("uses node crypto as a fallback", async () => {
		jest.setSystemTime(0)

		Object.defineProperty(globalThis, "crypto", { value: undefined, writable: true })

		await expect(TOTP.generate("JBSWY3DPEHPK3PXP")).resolves.toEqual(expect.objectContaining({ otp: "282760" }))
	})
})
