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

console.log(token); // prints a 6-digit time-based token based on provided key and current time
```

## Default token settings

- SHA-1
- 30-second epoch interval
- 6-digit tokens

## Custom token settings

Settings can be provided as an optional second parameter:

```javascript
var totp = require('totp-generator');

var token = totp('JBSWY3DPEHPK3PXP', {digits: 8});
console.log(token); // prints an 8-digit token

var token = totp('JBSWY3DPEHPK3PXP', {algorithm: 'SHA-512'});
console.log(token); // prints a token created using a different algorithm

var token = totp('JBSWY3DPEHPK3PXP', {period: 60});
console.log(token); // prints a token using a 60-second epoch interval

var token = totp('JBSWY3DPEHPK3PXP', {digits: 8, algorithm: 'SHA-512', period: 60});
console.log(token); // prints a token using all custom settings combined
```

## What do I use this library for?

- TOTP generation
- E2E tests (where you need to login with 2-factor authentication)
