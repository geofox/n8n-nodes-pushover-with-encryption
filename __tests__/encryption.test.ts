import { createHmac } from 'crypto';
import {
	encryptField,
	decryptField,
	generateKeyHex,
	PushoverEncryptionError,
} from '../nodes/Pushover/encryption';

const KEY = 'a'.repeat(64);
const FIXED_IV = Buffer.alloc(16, 0x42);

describe('Pushover encryption helper', () => {
	test('round-trips plaintext through encrypt → decrypt', () => {
		const plaintext = 'hellorld';
		const ct = encryptField(plaintext, KEY);
		expect(decryptField(ct, KEY)).toBe(plaintext);
	});

	test('handles multi-byte UTF-8 (emoji, accented chars)', () => {
		const plaintext = 'Ça marche 👍 — 漢字';
		const ct = encryptField(plaintext, KEY);
		expect(decryptField(ct, KEY)).toBe(plaintext);
	});

	test('handles long plaintext near Pushover 1024-byte limit', () => {
		const plaintext = 'x'.repeat(1024);
		const ct = encryptField(plaintext, KEY);
		expect(decryptField(ct, KEY)).toBe(plaintext);
	});

	test('produces deterministic output for a fixed IV', () => {
		const a = encryptField('same input', KEY, { iv: FIXED_IV });
		const b = encryptField('same input', KEY, { iv: FIXED_IV });
		expect(a).toBe(b);
	});

	test('produces different output across random IVs for the same input', () => {
		const a = encryptField('same input', KEY);
		const b = encryptField('same input', KEY);
		expect(a).not.toBe(b);
	});

	test('decryption rejects a tampered ciphertext', () => {
		const ct = encryptField('do not tamper', KEY);
		const blob = Buffer.from(ct, 'base64');
		// Flip a bit in the ciphertext body (skip IV).
		blob[20] ^= 0x01;
		const tampered = blob.toString('base64');
		expect(() => decryptField(tampered, KEY)).toThrow(PushoverEncryptionError);
	});

	test('decryption rejects a tampered HMAC', () => {
		const ct = encryptField('hmac me', KEY);
		const blob = Buffer.from(ct, 'base64');
		// Flip last byte (inside HMAC).
		blob[blob.length - 1] ^= 0x01;
		expect(() => decryptField(blob.toString('base64'), KEY)).toThrow(/HMAC/);
	});

	test('rejects non-hex / wrong-length keys', () => {
		expect(() => encryptField('x', 'tooshort')).toThrow(PushoverEncryptionError);
		expect(() => encryptField('x', 'z'.repeat(64))).toThrow(PushoverEncryptionError);
		expect(() => encryptField('x', 'a'.repeat(63))).toThrow(PushoverEncryptionError);
	});

	test('rejects an IV that is not exactly 16 bytes', () => {
		expect(() => encryptField('x', KEY, { iv: Buffer.alloc(15) })).toThrow(PushoverEncryptionError);
		expect(() => encryptField('x', KEY, { iv: Buffer.alloc(17) })).toThrow(PushoverEncryptionError);
	});

	test('decryption rejects a too-short payload', () => {
		const stub = Buffer.alloc(10).toString('base64');
		expect(() => decryptField(stub, KEY)).toThrow(PushoverEncryptionError);
	});

	test('generateKeyHex returns 64 hex characters that the helper accepts', () => {
		const k = generateKeyHex();
		expect(k).toMatch(/^[0-9a-f]{64}$/);
		expect(decryptField(encryptField('roundtrip', k), k)).toBe('roundtrip');
	});

	test('output is valid base64 and the right size shape (IV + ciphertext + HMAC)', () => {
		const ct = encryptField('size check', KEY, { iv: FIXED_IV });
		const blob = Buffer.from(ct, 'base64');
		// 16 IV + N ciphertext (multiple of 16, ≥16) + 32 HMAC
		expect(blob.length).toBeGreaterThanOrEqual(16 + 16 + 32);
		expect((blob.length - 16 - 32) % 16).toBe(0);
		expect(blob.subarray(0, 16).equals(FIXED_IV)).toBe(true);
	});

	test('empty string round-trips through encrypt → decrypt', () => {
		const ct = encryptField('', KEY);
		expect(decryptField(ct, KEY)).toBe('');
	});

	test('decrypt of a MAC-valid but non-gzip ciphertext throws PushoverEncryptionError', () => {
		// Forge a payload that passes HMAC validation but contains random bytes
		// in place of a real ciphertext — exercises the decipher/gunzip error
		// path that previously surfaced as an unwrapped zlib Error.
		const key = Buffer.from(KEY, 'hex');
		const iv = Buffer.alloc(16, 0x11);
		const fakeCiphertext = Buffer.alloc(32, 0x22); // 2 AES blocks of junk
		const mac = createHmac('sha256', key)
			.update(Buffer.concat([iv, fakeCiphertext]))
			.digest();
		const payload = Buffer.concat([iv, fakeCiphertext, mac]).toString('base64');

		expect(() => decryptField(payload, KEY)).toThrow(PushoverEncryptionError);
		expect(() => decryptField(payload, KEY)).toThrow(/Decryption failed/);
	});

	test('gunzip failure surfaces as PushoverEncryptionError, not zlib Error', () => {
		// Construct a payload that decrypts cleanly (correct AES padding) but
		// whose decrypted bytes are not a valid gzip stream. We do this by
		// encrypting a non-gzip buffer with the same AES-CBC step we use
		// internally, then attaching a correct HMAC.
		const { createCipheriv } = require('crypto');
		const key = Buffer.from(KEY, 'hex');
		const iv = Buffer.alloc(16, 0x33);
		const cipher = createCipheriv('aes-256-cbc', key, iv);
		const plaintextNotGzip = Buffer.from('this is plaintext, not gzip\n'.repeat(2));
		const ct = Buffer.concat([cipher.update(plaintextNotGzip), cipher.final()]);
		const mac = createHmac('sha256', key)
			.update(Buffer.concat([iv, ct]))
			.digest();
		const payload = Buffer.concat([iv, ct, mac]).toString('base64');

		expect(() => decryptField(payload, KEY)).toThrow(PushoverEncryptionError);
	});
});
