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
});
