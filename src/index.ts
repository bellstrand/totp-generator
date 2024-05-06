import JsSHA from "jssha"

export type TOTPAlgorithm = "SHA-1" | "SHA-224" | "SHA-256" | "SHA-384" | "SHA-512" | "SHA3-224" | "SHA3-256" | "SHA3-384" | "SHA3-512"

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

export class TOTP {
	/**
	 * Generates a Time-based One-Time Password (TOTP).
	 * @param {string} key - The secret key for TOTP.
	 * @param {Options} options - Optional parameters for TOTP.
	 * @returns An object containing the OTP and its expiry time.
	 */
	static generate(key: string, options?: Options) {
		const _options: Required<Options> = { digits: 6, algorithm: "SHA-1", period: 30, timestamp: Date.now(), ...options }
		const epoch = Math.floor(_options.timestamp / 1000.0)
		const time = this.leftpad(this.dec2hex(Math.floor(epoch / _options.period)), 16, "0")

		const shaObj = new JsSHA(_options.algorithm, "HEX")

		shaObj.setHMACKey(this.base32tohex(key), "HEX")
		shaObj.update(time)

		const hmac = shaObj.getHMAC("HEX")
		const offset = this.hex2dec(hmac.substring(hmac.length - 1)) * 2

		let otp = (this.hex2dec(hmac.slice(offset, offset + 8)) & this.hex2dec("7fffffff")) + ""
		const start = Math.max(otp.length - _options.digits, 0)

		otp = otp.substring(start, start + _options.digits)

		const expires = Math.ceil((_options.timestamp + 1) / (_options.period * 1000)) * _options.period * 1000

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
	 * Converts a base32 string to a hexadecimal string.
	 * @param {string} base32 - The base32 string.
	 * @returns {string} The hex representation.
	 */
	private static base32tohex(base32: string): string {
		const base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
		let bits = ""
		let hex = ""

		const _base32 = base32.replace(/=+$/, "")

		for (let i = 0; i < _base32.length; i++) {
			const val = base32chars.indexOf(_base32.charAt(i).toUpperCase())
			if (val === -1) throw new Error("Invalid base32 character in key")
			bits += this.leftpad(val.toString(2), 5, "0")
		}

		for (let i = 0; i + 8 <= bits.length; i += 8) {
			const chunk = bits.slice(i, i + 8)
			hex = hex + this.leftpad(parseInt(chunk, 2).toString(16), 2, "0")
		}
		return hex
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
}