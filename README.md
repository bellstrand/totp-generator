# totp-generator

totp-generator lets you generate TOTP tokens from a TOTP key

## How to use

```node
const totp = require('totp-generator')

let token = totp('SHA-256', 30, 6, 'JBSWY3DPEHPK3PXP')

console.log(token); // prints a 6 digit time base token based on inputed key and time
```

## Works with these token variables

- SHA-1, SHA-256, SHA-512
- epoch interval based on seconds
- 6 digit tokens

## What do I use this library for?

- E2E tests (where you need to login with 2-factor authentication)

### Forked from

https://github.com/bellstrand/totp-generator
