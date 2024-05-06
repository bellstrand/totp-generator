export type TOTPAlgorithm = "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512"

/**
 * Options for TOTP generation.
 * @param {number} [digits=6] - The number of digits in the OTP.
 * @param {TOTPAlgorithm} [algorithm="SHA-1"] - Algorithm used for hashing.
 * @param {number} [period=30] - The time period for OTP validity in seconds.
 * @param {number} [timestamp=Date.now()] - The current timestamp.
 */
type Options = {
	digits?: number
	algorithm?: TOTPAlgorithm
	period?: number
	timestamp?: number
}

const crypto = globalThis.crypto.subtle

export class TOTP {
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
			period: 30,
			timestamp: Date.now(),
			...options
		}
		const epochSeconds = Math.floor(_options.timestamp / 1000)
		const timeHex = this.leftpad(this.dec2hex(Math.floor(epochSeconds / _options.period)), 16, "0")
		const keyBuffer = this.base32ToBuffer(key)

		const hmacKey = await crypto.importKey("raw", keyBuffer, { name: "HMAC", hash: { name: _options.algorithm } }, false, ["sign"])
		const signature = await crypto.sign("HMAC", hmacKey, this.hex2buf(timeHex))
		const signatureHex = this.buf2hex(signature)

		const offset = this.hex2dec(signatureHex.slice(-1)) * 2
		let otp = (this.hex2dec(signatureHex.slice(offset, offset + 8)) & 0x7fffffff).toString()
		otp = otp.slice(-_options.digits)

		const nextPeriod = Math.ceil((_options.timestamp + 1) / (_options.period * 1000)) * _options.period * 1000

		return { otp, expires: nextPeriod }
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
	 * Left-pads a string with a specified character to a specified length.
	 * @param {string} str - The initial string.
	 * @param {number} len - The target length.
	 * @param {string} pad - The padding character.
	 * @returns {string} The padded string.
	 */
	private static leftpad(str: string, len: number, pad: string): string {
		if (len + 1 >= str.length) {
			str = Array(len + 1 - str.length).join(pad) + str
		}
		return str
	}

	/**
	 * Converts a base32 encoded string to an ArrayBuffer.
	 * @param {string} base32String - The base32 encoded string to convert.
	 * @returns {ArrayBuffer} The ArrayBuffer representation of the base32 encoded string.
	 */
	private static base32ToBuffer(base32String: string): ArrayBuffer {
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
		const lookup = new Uint8Array(256).fill(255)
		for (let i = 0; i < alphabet.length; i++) {
			lookup[alphabet.charCodeAt(i)] = i
		}

		let length = base32String.length

		while (base32String.charCodeAt(length - 1) === 61) length-- // Remove pads

		const bufferSize = (length * 5) / 8 // Estimate buffer size
		const buffer = new Uint8Array(bufferSize)
		let value = 0,
			bits = 0,
			index = 0

		for (let i = 0; i < length; i++) {
			const charCode = lookup[base32String.charCodeAt(i)]
			if (charCode === 255) throw new Error("Invalid base32 character in key")
			value = (value << 5) | charCode
			bits += 5

			if (bits >= 8) {
				buffer[index++] = (value >>> (bits - 8)) & 255
				bits -= 8
			}
		}
		return buffer.buffer as ArrayBuffer
	}

	/**
	 * Converts a hexadecimal string to an ArrayBuffer.
	 * @param {string} hex - The hexadecimal string to convert.
	 * @returns {ArrayBuffer} The ArrayBuffer representation of the hexadecimal string.
	 */
	private static hex2buf(hex: string): ArrayBuffer {
		const buffer = new Uint8Array(hex.length / 2);

		for (let i = 0, j = 0; i < hex.length; i += 2, j++) {
			buffer[j] = parseInt(hex.substring(i, i + 2), 16);
		}

		return buffer.buffer as ArrayBuffer;
	}

	/**
	 * Converts an ArrayBuffer to a hexadecimal string.
	 * @param {ArrayBuffer} buffer - The ArrayBuffer to convert.
	 * @returns {string} The hexadecimal string representation of the buffer.
	 */
	private static buf2hex(buffer: ArrayBuffer): string {
		return [...new Uint8Array(buffer)].map((x) => x.toString(16).padStart(2, "0")).join("")
	}
}