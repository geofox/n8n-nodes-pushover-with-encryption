import { createCipheriv, createDecipheriv, createHmac } from 'crypto';
import {
	encryptField,
	decryptField,
	generateKeyHex,
	PushoverEncryptionError,
} from '../nodes/Pushover/encryption';

const KEY = 'a'.repeat(64);
const FIXED_IV = Buffer.alloc(16, 0x42);

// Known-answer fixtures produced by the reference pipeline from the README
// (GNU `gzip -9` | `openssl enc -aes-256-cbc` | `openssl dgst -sha256 -mac HMAC`)
// with a fixed IV (a0 a1 … af), so they are independent of this package's
// implementation. The key is the public test vector 00 01 02 … 1f.
const KAT_KEY = Buffer.from(Array.from({ length: 32 }, (_, i) => i)).toString('hex');
const KAT = {
	hellorld:
		'oKGio6SlpqeoqaqrrK2ur36Fa2sQSDZNFTKOYTGEKLbD7oNFrB2DhbQaVRVyBEAZDcqJh0iXIxnqo19aC5LKXIdfYixMSItQmOT8lgB5WYc=',
	'Ça marche 👍 — 漢字':
		'oKGio6SlpqeoqaqrrK2urzSO3okrEGJFctGSudhsGjfkBMTg4eGOWUCu77oZw4Yxe54Gic2qbP8lxZy6ya1FvSnEpsYkxiOD9wFwSFcH4PFO7/tRq8Wp0qO4OHlCZa/h',
};

describe('Pushover encryption helper', () => {
	test('round-trips plaintext through encrypt → decrypt', async () => {
		const plaintext = 'hellorld';
		const ct = await encryptField(plaintext, KEY);
		await expect(decryptField(ct, KEY)).resolves.toBe(plaintext);
	});

	test('handles multi-byte UTF-8 (emoji, accented chars)', async () => {
		const plaintext = 'Ça marche 👍 — 漢字';
		const ct = await encryptField(plaintext, KEY);
		await expect(decryptField(ct, KEY)).resolves.toBe(plaintext);
	});

	test('handles long plaintext near Pushover 1024-byte limit', async () => {
		const plaintext = 'x'.repeat(1024);
		const ct = await encryptField(plaintext, KEY);
		await expect(decryptField(ct, KEY)).resolves.toBe(plaintext);
	});

	test.each(Object.entries(KAT))(
		'decrypts a payload produced by the OpenSSL + gzip reference pipeline (%s)',
		async (plaintext, payload) => {
			await expect(decryptField(payload, KAT_KEY)).resolves.toBe(plaintext);
		},
	);

	test('the AES layer wraps a standard gzip stream, as the spec requires', async () => {
		const ct = await encryptField('spec check', KEY, { iv: FIXED_IV });
		const blob = Buffer.from(ct, 'base64');
		const decipher = createDecipheriv('aes-256-cbc', Buffer.from(KEY, 'hex'), FIXED_IV);
		const inner = Buffer.concat([decipher.update(blob.subarray(16, -32)), decipher.final()]);
		// RFC 1952: ID1 ID2 = 1f 8b, CM = 8 (deflate)
		expect(inner.subarray(0, 3).toString('hex')).toBe('1f8b08');
	});

	test('produces deterministic output for a fixed IV', async () => {
		const a = await encryptField('same input', KEY, { iv: FIXED_IV });
		const b = await encryptField('same input', KEY, { iv: FIXED_IV });
		expect(a).toBe(b);
	});

	test('produces different output across random IVs for the same input', async () => {
		const a = await encryptField('same input', KEY);
		const b = await encryptField('same input', KEY);
		expect(a).not.toBe(b);
	});

	test('decryption rejects a tampered ciphertext', async () => {
		const ct = await encryptField('do not tamper', KEY);
		const blob = Buffer.from(ct, 'base64');
		// Flip a bit in the ciphertext body (skip IV).
		blob[20] ^= 0x01;
		const tampered = blob.toString('base64');
		await expect(decryptField(tampered, KEY)).rejects.toThrow(PushoverEncryptionError);
	});

	test('decryption rejects a tampered HMAC', async () => {
		const ct = await encryptField('hmac me', KEY);
		const blob = Buffer.from(ct, 'base64');
		// Flip last byte (inside HMAC).
		blob[blob.length - 1] ^= 0x01;
		await expect(decryptField(blob.toString('base64'), KEY)).rejects.toThrow(/HMAC/);
	});

	test('rejects non-hex / wrong-length keys', async () => {
		await expect(encryptField('x', 'tooshort')).rejects.toThrow(PushoverEncryptionError);
		await expect(encryptField('x', 'z'.repeat(64))).rejects.toThrow(PushoverEncryptionError);
		await expect(encryptField('x', 'a'.repeat(63))).rejects.toThrow(PushoverEncryptionError);
	});

	test('rejects an IV that is not exactly 16 bytes', async () => {
		await expect(encryptField('x', KEY, { iv: Buffer.alloc(15) })).rejects.toThrow(
			PushoverEncryptionError,
		);
		await expect(encryptField('x', KEY, { iv: Buffer.alloc(17) })).rejects.toThrow(
			PushoverEncryptionError,
		);
	});

	test('decryption rejects a too-short payload', async () => {
		const stub = Buffer.alloc(10).toString('base64');
		await expect(decryptField(stub, KEY)).rejects.toThrow(PushoverEncryptionError);
	});

	test('generateKeyHex returns 64 hex characters that the helper accepts', async () => {
		const k = generateKeyHex();
		expect(k).toMatch(/^[0-9a-f]{64}$/);
		await expect(decryptField(await encryptField('roundtrip', k), k)).resolves.toBe('roundtrip');
	});

	test('output is valid base64 and the right size shape (IV + ciphertext + HMAC)', async () => {
		const ct = await encryptField('size check', KEY, { iv: FIXED_IV });
		const blob = Buffer.from(ct, 'base64');
		// 16 IV + N ciphertext (multiple of 16, ≥16) + 32 HMAC
		expect(blob.length).toBeGreaterThanOrEqual(16 + 16 + 32);
		expect((blob.length - 16 - 32) % 16).toBe(0);
		expect(blob.subarray(0, 16).equals(FIXED_IV)).toBe(true);
	});

	test('empty string round-trips through encrypt → decrypt', async () => {
		const ct = await encryptField('', KEY);
		await expect(decryptField(ct, KEY)).resolves.toBe('');
	});

	test('decrypt of a MAC-valid but non-gzip ciphertext throws PushoverEncryptionError', async () => {
		// Forge a payload that passes HMAC validation but contains random bytes
		// in place of a real ciphertext — exercises the decipher/gunzip error
		// path so it never surfaces as an unwrapped crypto or stream error.
		const key = Buffer.from(KEY, 'hex');
		const iv = Buffer.alloc(16, 0x11);
		const fakeCiphertext = Buffer.alloc(32, 0x22); // 2 AES blocks of junk
		const mac = createHmac('sha256', key)
			.update(Buffer.concat([iv, fakeCiphertext]))
			.digest();
		const payload = Buffer.concat([iv, fakeCiphertext, mac]).toString('base64');

		await expect(decryptField(payload, KEY)).rejects.toThrow(PushoverEncryptionError);
		await expect(decryptField(payload, KEY)).rejects.toThrow(/Decryption failed/);
	});

	test('accepts a key with surrounding whitespace (e.g. trailing newline from openssl)', async () => {
		const padded = `  \n${KEY}\n  `;
		await expect(encryptField('hi', padded)).resolves.toEqual(expect.any(String));
		await expect(decryptField(await encryptField('hi', padded), padded)).resolves.toBe('hi');
	});

	test('gunzip failure surfaces as PushoverEncryptionError, not a stream error', async () => {
		// Construct a payload that decrypts cleanly (correct AES padding) but
		// whose decrypted bytes are not a valid gzip stream. We do this by
		// encrypting a non-gzip buffer with the same AES-CBC step we use
		// internally, then attaching a correct HMAC.
		const key = Buffer.from(KEY, 'hex');
		const iv = Buffer.alloc(16, 0x33);
		const cipher = createCipheriv('aes-256-cbc', key, iv);
		const plaintextNotGzip = Buffer.from('this is plaintext, not gzip\n'.repeat(2));
		const ct = Buffer.concat([cipher.update(plaintextNotGzip), cipher.final()]);
		const mac = createHmac('sha256', key)
			.update(Buffer.concat([iv, ct]))
			.digest();
		const payload = Buffer.concat([iv, ct, mac]).toString('base64');

		await expect(decryptField(payload, KEY)).rejects.toThrow(PushoverEncryptionError);
	});
});
