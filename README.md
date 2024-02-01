# totp-generator

[![Test](https://github.com/bellstrand/totp-generator/workflows/Test/badge.svg)](https://github.com/bellstrand/totp-generator/actions?query=workflow%3ATest)
[![Test Coverage](https://api.codeclimate.com/v1/badges/5ea846f544cbf46ffcee/test_coverage)](https://codeclimate.com/github/bellstrand/totp-generator/test_coverage)
[![npm Version](https://img.shields.io/npm/v/totp-generator.svg)](https://www.npmjs.com/package/totp-generator)

totp-generator lets you generate TOTP tokens from a TOTP key

## How to use

```javascript
import { TOTP } from "totp-generator"

// Keys provided must be base32 strings, ie. only containing characters matching (A-Z, 2-7, =).
const { otp, expires } = TOTP.generate("JBSWY3DPEHPK3PXP")

console.log(otp) // prints a 6-digit time-based token based on provided key and current time
```

## Default token settings

- SHA-1
- 30-second epoch interval
- 6-digit tokens

## Custom token settings

Settings can be provided as an optional second parameter:

```javascript
import { TOTP } from "totp-generator"

const { otp } = TOTP.generate("JBSWY3DPEHPK3PXP", { digits: 8 })
console.log(token) // prints an 8-digit token

const { otp } = TOTP.generate("JBSWY3DPEHPK3PXP", { algorithm: "SHA-512" })
console.log(token) // prints a token created using a different algorithm

const { otp } = TOTP.generate("JBSWY3DPEHPK3PXP", { period: 60 })
console.log(token) // prints a token using a 60-second epoch interval

const { otp } = TOTP.generate("JBSWY3DPEHPK3PXP", { timestamp: 1465324707000 })
console.log(token) // prints a token for given time

const { otp } = TOTP.generate("JBSWY3DPEHPK3PXP", {
	digits: 8,
	algorithm: "SHA-512",
	period: 60,
	timestamp: 1465324707000,
})
console.log(token) // prints a token using all custom settings combined
```

## What do I use this library for?

- TOTP generation
- E2E tests (where you need to login with 2-factor authentication)
