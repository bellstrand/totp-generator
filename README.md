# totp-generator

[![Test](https://github.com/bellstrand/totp-generator/workflows/Test/badge.svg)](https://github.com/bellstrand/totp-generator/actions?query=workflow%3ATest)
[![Code Climate](https://codeclimate.com/github/bellstrand/totp-generator/badges/gpa.svg)](https://codeclimate.com/github/bellstrand/totp-generator)
[![Test Coverage](https://codeclimate.com/github/bellstrand/totp-generator/badges/coverage.svg)](https://codeclimate.com/github/bellstrand/totp-generator/coverage)
[![npm Version](https://img.shields.io/npm/v/totp-generator.svg)](https://www.npmjs.com/package/totp-generator)

totp-generator lets you generate TOTP tokens from a TOTP key

## How to use

```javascript
const totp = require("totp-generator");

const token = totp("JBSWY3DPEHPK3PXP");

console.log(token); // prints a 6-digit time-based token based on provided key and current time
```

## Default token settings

- SHA-1
- 30-second epoch interval
- 6-digit tokens

## Custom token settings

Settings can be provided as an optional second parameter:

```javascript
const totp = require("totp-generator");

const token = totp("JBSWY3DPEHPK3PXP", { digits: 8 });
console.log(token); // prints an 8-digit token

const token = totp("JBSWY3DPEHPK3PXP", { algorithm: "SHA-512" });
console.log(token); // prints a token created using a different algorithm

const token = totp("JBSWY3DPEHPK3PXP", { period: 60 });
console.log(token); // prints a token using a 60-second epoch interval

const token = totp("JBSWY3DPEHPK3PXP", {
	digits: 8,
	algorithm: "SHA-512",
	period: 60,
});
console.log(token); // prints a token using all custom settings combined
```

## What do I use this library for?

- TOTP generation
- E2E tests (where you need to login with 2-factor authentication)
