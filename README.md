# totp-generator

totp-generator lets you generate TOTP tokens from a TOTP key

## How to use

```node
const totp = require('totp-generator')

const token = totp(30, 6, 'JBSWY3DPEHPK3PXP')

console.log(token); // prints a 6 digit time base token based on inputed key and time
```

## Works with these token variables

- SHA-512
- epoch interval based on seconds
- token size based on variable

## What do I use this library for?

- E2E tests (where you need to login with 2-factor authentication)