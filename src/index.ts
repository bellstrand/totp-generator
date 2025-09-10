export type TOTPAlgorithm = "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512"
export type TOTPEncoding = "hex" | "ascii"

/**
 * Options for TOTP generation.
 * @param {number} [digits=6] - The number of digits in the OTP.
 * @param {TOTPAlgorithm} [algorithm="SHA-1"] - Algorithm used for hashing.
 * @param {TOTPEncoding} [encoding="hex"] - Encoding used for the OTP.
 * @param {number} [period=30] - The time period for OTP validity in seconds.
 * @param {number} [timestamp=Date.now()] - The current timestamp.
 * @param {boolean} [explicitZeroPad=false] - If true, pads the OTP with leading zeros to match the desired number of digits.
 */
type Options = {
	digits?: number
	algorithm?: TOTPAlgorithm
	encoding?: TOTPEncoding
	period?: number
	timestamp?: number
	explicitZeroPad?: boolean
}

export class TOTP {
	/**
	 * An internal, swappable function for performing HMAC signing.
	 * This allows replacement of the crypto implementation.
	 * @internal
	 * @param {ArrayBuffer} keyBuffer - The secret key.
	 * @param {string} dataHex - The data to sign, as a hexadecimal string.
	 * @param {TOTPAlgorithm} algorithm - The hashing algorithm to use.
	 * @returns {Promise<ArrayBuffer>} A promise that resolves to the signature.
	 */
	private static _sign = async (keyBuffer: ArrayBuffer, dataHex: string, algorithm: TOTPAlgorithm): Promise<ArrayBuffer> => {
		/* istanbul ignore next */
		try {
			// Prioritize global Web Crypto API (browsers, Deno, Cloudflare Workers, etc.)
			// or Node.js's implementation. This is the fastest and most secure method.
			const crypto = (globalThis.crypto || require("node:crypto").webcrypto).subtle
			const hmacKey = await crypto.importKey("raw", keyBuffer, { name: "HMAC", hash: { name: algorithm } }, false, ["sign"])
			const dataBuffer = TOTP.hex2buf(dataHex)
			return await crypto.sign("HMAC", hmacKey, dataBuffer)
		} catch (_error) {
			// If native crypto fails (e.g., in a restricted edge environment or old browser),
			// fall back to the JS implementation. This is a robust catch-all.
			const { default: jsSHA } = await import("jssha")
			const hmac = new jsSHA(algorithm, "ARRAYBUFFER")
			hmac.setHMACKey(keyBuffer, "ARRAYBUFFER")
			hmac.update(TOTP.hex2buf(dataHex))
			return hmac.getHMAC("ARRAYBUFFER")
		}
	}

	/**
	 * Generates a Time-based One-Time Password (TOTP).
	 * @async
	 * @param {string} key - The secret key for TOTP.
	 * @param {Options} options - Optional parameters for TOTP.
	 * @returns {Promise<{otp: string, expires: number}>} A promise that resolves to an object containing the OTP and its expiry time.
	 */
	static async generate(key: string, options?: Options): Promise<{ otp: string; expires: number }> {
		const _options: Required<Options> = {
			digits: 6,
			algorithm: "SHA-1",
			encoding: "hex",
			period: 30,
			timestamp: Date.now(),
			explicitZeroPad: false,
			...options,
		}
		const epochSeconds = Math.floor(_options.timestamp / 1000)
		const timeHex = TOTP.dec2hex(Math.floor(epochSeconds / _options.period)).padStart(16, "0")

		const keyBuffer = _options.encoding === "hex" ? TOTP.base32ToBuffer(key) : TOTP.asciiToBuffer(key)

		const signature = await TOTP._sign(keyBuffer, timeHex, _options.algorithm)

		const signatureHex = TOTP.buf2hex(signature)
		const offset = TOTP.hex2dec(signatureHex.slice(-1)) * 2
		const masked = TOTP.hex2dec(signatureHex.slice(offset, offset + 8)) & 0x7fffffff
		const otpString = masked.toString().slice(-_options.digits)
		const otp = _options.explicitZeroPad ? otpString.padStart(_options.digits, "0") : otpString

		const period = _options.period * 1000
		const expires = Math.ceil((_options.timestamp + 1) / period) * period

		return { otp, expires }
	}

	/**
	 * Converts a hexadecimal string to a decimal number.
	 * @param {string} hex - The hex string.
	 * @returns {number} The decimal representation.
	 */
	private static hex2dec(hex: string): number {
		return parseInt(hex, 16)
	}

	/**
	 * Converts a decimal number to a hexadecimal string.
	 * @param {number} dec - The decimal number.
	 * @returns {string} The hex representation.
	 */
	private static dec2hex(dec: number): string {
		return (dec < 15.5 ? "0" : "") + Math.round(dec).toString(16)
	}

	/**
	 * Converts a base32 encoded string to an ArrayBuffer.
	 * @param {string} str - The base32 encoded string to convert.
	 * @returns {ArrayBuffer} The ArrayBuffer representation of the base32 encoded string.
	 */
	private static base32ToBuffer(str: string): ArrayBuffer {
		str = str.toUpperCase()
		let length = str.length
		while (str.charCodeAt(length - 1) === 61) length-- // Remove pads

		const bufferSize = (length * 5) / 8 // Estimate buffer size
		const buffer = new Uint8Array(bufferSize)
		let value = 0
		let bits = 0
		let index = 0

		for (let i = 0; i < length; i++) {
			const charCode = TOTP.base32[str.charCodeAt(i)]
			if (charCode === undefined) throw new Error("Invalid base32 character in key")
			value = (value << 5) | charCode
			bits += 5
			if (bits >= 8) buffer[index++] = value >>> (bits -= 8)
		}
		return buffer.buffer as ArrayBuffer
	}

	/**
	 * Converts an ASCII string to an ArrayBuffer.
	 * @param {string} str - The ASCII string to convert.
	 * @returns {ArrayBuffer} The ArrayBuffer representation of the ASCII string.
	 */
	private static asciiToBuffer(str: string): ArrayBuffer {
		const buffer = new Uint8Array(str.length)
		for (let i = 0; i < str.length; i++) {
			buffer[i] = str.charCodeAt(i)
		}
		return buffer.buffer as ArrayBuffer
	}

	/**
	 * Converts a hexadecimal string to an ArrayBuffer.
	 * @param {string} hex - The hexadecimal string to convert.
	 * @returns {ArrayBuffer} The ArrayBuffer representation of the hexadecimal string.
	 */
	private static hex2buf(hex: string): ArrayBuffer {
		const buffer = new Uint8Array(hex.length / 2)
		for (let i = 0, j = 0; i < hex.length; i += 2, j++) buffer[j] = TOTP.hex2dec(hex.slice(i, i + 2))
		return buffer.buffer as ArrayBuffer
	}

	/**
	 * Converts an ArrayBuffer to a hexadecimal string.
	 * @param {ArrayBuffer} buffer - The ArrayBuffer to convert.
	 * @returns {string} The hexadecimal string representation of the buffer.
	 */
	private static buf2hex(buffer: ArrayBuffer): string {
		return [...new Uint8Array(buffer)].map((x) => x.toString(16).padStart(2, "0")).join("")
	}

	/**
	 * A precalculated mapping from base32 character codes to their corresponding index values for performance optimization.
	 * This mapping is used in the base32ToBuffer method to convert base32 encoded strings to their binary representation.
	 */
	private static readonly base32: { [key: number]: number } = {
		50: 26, 51: 27, 52: 28, 53: 29, 54: 30, 55: 31, 65: 0, 66: 1, 67: 2, 68: 3, 69: 4, 70: 5, 71: 6,
		72: 7, 73: 8, 74: 9, 75: 10, 76: 11, 77: 12, 78: 13, 79: 14, 80: 15, 81: 16, 82: 17, 83: 18,
		84: 19, 85: 20, 86: 21, 87: 22, 88: 23, 89: 24, 90: 25,
	}
}
