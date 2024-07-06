import { describe, test, expect } from "bun:test"
import { TOTP, TOTPAlgorithm } from "."

const start = 1665644340000
describe("totp generation", () => {
	test("should generate token with lowercase chars", () => {
		expect(TOTP.generate("jBSwy3DPehpk3pxp", { timestamp: 0 })).resolves.toEqual(expect.objectContaining({ otp: "282760" }))
	})
	
	test("should generate token with date now = 1971", () => {
		expect(TOTP.generate("JBSWY3DPEHPK3PXP", { timestamp: 0 })).resolves.toEqual(expect.objectContaining({ otp: "282760" }))
	})

	test("should generate token with date now = 2016", () => {
		expect(TOTP.generate("JBSWY3DPEHPK3PXP", { timestamp: 1465324707000 })).resolves.toEqual(expect.objectContaining({ otp: "341128" }))
	})

	test("should generate correct token at the start of the cycle", () => {
		expect(TOTP.generate("JBSWY3DPEHPK3PXP", { timestamp: start + 1 })).resolves.toEqual(expect.objectContaining({ otp: "886842" }))
	})

	test("should generate correct token at the end of the cycle", () => {
		expect(TOTP.generate("JBSWY3DPEHPK3PXP", { timestamp: start - 1 })).resolves.toEqual(expect.objectContaining({ otp: "134996" }))
	})

	test("should generate token with a leading zero", () => {
		expect(TOTP.generate("JBSWY3DPEHPK3PXP", { timestamp: 1365324707000 })).resolves.toEqual(expect.objectContaining({ otp: "089029" }))
	})

	test("should generate token from a padded base32 key", () => {
		expect(TOTP.generate("CI2FM6EQCI2FM6EQKU======", { timestamp: 1465324707000 })).resolves.toEqual(expect.objectContaining({ otp: "984195" }))
	})

	test("should throw if key contains an invalid character", () => {
		expect(TOTP.generate("ABSWY3DPEHPK3!@#", { timestamp: 1465324707000 })).rejects.toThrow("Invalid base32 character in key")
	})

	test("should generate longer-lasting token with date now = 2016", () => {
		expect(TOTP.generate("JBSWY3DPEHPK3PXP", { period: 60, timestamp: 1465324707000 })).resolves.toEqual(expect.objectContaining({ otp: "313995" }))
	})

	test("should generate longer token with date now = 2016", () => {
		expect(TOTP.generate("JBSWY3DPEHPK3PXP", { digits: 8, timestamp: 1465324707000 })).resolves.toEqual(expect.objectContaining({ otp: "43341128" }))
	})

	test("should generate SHA-512-based token with date now = 2016", () => {
		expect(TOTP.generate("JBSWY3DPEHPK3PXP", { algorithm: "SHA-512", timestamp: 1465324707000 })).resolves.toEqual(expect.objectContaining({ otp: "093730" }))
	})

	test.each([
		{ algorithm: "SHA-1", expected: "341128" },
		{ algorithm: "SHA-256", expected: "461529" },
		{ algorithm: "SHA-384", expected: "988682" },
		{ algorithm: "SHA-512", expected: "093730" },
	] as { algorithm: TOTPAlgorithm; expected: string }[])("should generate token based on %p algorithm", ({ algorithm, expected }) => {
		expect(TOTP.generate("JBSWY3DPEHPK3PXP", { algorithm, timestamp: 1465324707000 })).resolves.toEqual(expect.objectContaining({ otp: expected }))
	})

	test("should generate token with timestamp from options", () => {
		expect(TOTP.generate("JBSWY3DPEHPK3PXP", { timestamp: 1465324707000 })).resolves.toEqual(expect.objectContaining({ otp: "341128" }))
	})

	test("should return all values when values is less then digits", () => {
		expect(TOTP.generate("3IS523AYRNFUE===", { digits: 9, timestamp: 1634193300000 })).resolves.toEqual(expect.objectContaining({ otp: "97859470" }))
	})

	test("should trigger leftpad fix", () => {
		expect(TOTP.generate("JBSWY3DPEHPK3PXP", { timestamp: 12312354132421332222222222 })).resolves.toEqual(expect.objectContaining({ otp: "895896" }))
	})

	test("should generate token with correct expires", () =>{
		expect(TOTP.generate("JBSWY3DPEHPK3PXP", { timestamp: start - 1 })).resolves.toEqual({ otp: "134996", expires: start })
		expect(TOTP.generate("JBSWY3DPEHPK3PXP", { timestamp: start })).resolves.toEqual({ otp: "886842", expires: start + 30000 })
		expect(TOTP.generate("JBSWY3DPEHPK3PXP", { timestamp: start + 1 })).resolves.toEqual({ otp: "886842", expires: start + 30000 })
		expect(TOTP.generate("JBSWY3DPEHPK3PXP", { timestamp: start + 29999 })).resolves.toEqual({ otp: "886842", expires: start + 30000 })
		expect(TOTP.generate("JBSWY3DPEHPK3PXP", { timestamp: start + 30000 })).resolves.toEqual({ otp: "421127", expires: start + 60000 })
		expect(TOTP.generate("JBSWY3DPEHPK3PXP", { timestamp: start + 30001 })).resolves.toEqual({ otp: "421127", expires: start + 60000 })
	})

	test("uses node crypto as a fallback", async () => {
		Object.defineProperty(globalThis, "crypto", { value: undefined, writable: true })

		expect(TOTP.generate("JBSWY3DPEHPK3PXP", { timestamp: 0 })).resolves.toEqual(expect.objectContaining({ otp: "282760" }))
	})
})

describe("TOTP generation with ASCII keys", () => {
  test.each([
    { time: 59, expectedOtp: "94287082" },
    { time: 1111111109, expectedOtp: "07081804" },
    { time: 1111111111, expectedOtp: "14050471" },
    { time: 1234567890, expectedOtp: "89005924" },
    { time: 2000000000, expectedOtp: "69279037" },
    { time: 20000000000, expectedOtp: "65353130" },
  ])("should generate correct OTP for time $time", async ({ time, expectedOtp }) => {
    await expect(TOTP.generate("12345678901234567890", { encoding: "ascii", digits: 8, timestamp: time * 1000 })).resolves.toEqual(
      expect.objectContaining({ otp: expectedOtp })
    );
  });
});