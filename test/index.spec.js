'use strict';

let totp = require('../index');

describe('totp generation', () => {
	it('should generate token with date now = 1971', () => {
		global.Date.now = () => { return 0; };
		expect(totp('JBSWY3DPEHPK3PXP')).toEqual('282760');
	});

	it('should generate token with date now = 2016', () => {
		global.Date.now = () => { return 1465324707000; };
		expect(totp('JBSWY3DPEHPK3PXP')).toEqual('341128');
	});

	it('should generate token with a leading zero', () => {
		global.Date.now = () => { return 1365324707000; };
		expect(totp('JBSWY3DPEHPK3PXP')).toEqual('089029');
	});
});
