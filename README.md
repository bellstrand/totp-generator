# totp-generator

[![Build Status](https://travis-ci.org/bellstrand/totp-generator.svg?branch=master)](https://travis-ci.org/bellstrand/totp-generator)
[![Code Climate](https://codeclimate.com/github/bellstrand/totp-generator/badges/gpa.svg)](https://codeclimate.com/github/bellstrand/totp-generator)
[![Test Coverage](https://codeclimate.com/github/bellstrand/totp-generator/badges/coverage.svg)](https://codeclimate.com/github/bellstrand/totp-generator/coverage)
[![npm Version](https://img.shields.io/npm/v/totp-generator.svg)](https://www.npmjs.com/package/totp-generator)

totp-generator lets you generate TOTP tokens from a TOTP key

## How to use

```javascript
var totp = require('totp-generator');

var token = totp('JBSWY3DPEHPK3PXP');

console.log(token); // prints a 6 digit time base token based on inputed key and time
```

## Works with these token requirements

- SHA-1
- 30 sec epoch interval
- 6 digit tokens

## What do I use this library for?

- E2E tests (where you need to login with 2-factor authentication)
