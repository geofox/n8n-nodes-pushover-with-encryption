import { createCipheriv, createDecipheriv, createHmac, randomBytes, timingSafeEqual } from 'crypto';
import { gunzipSync, gzipSync } from 'zlib';

const HEX_KEY_RE = /^[0-9a-fA-F]{64}$/;
const IV_LEN = 16;
const HMAC_LEN = 32;

export class PushoverEncryptionError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'PushoverEncryptionError';
	}
}

function parseKey(keyHex: string): Buffer {
	if (!HEX_KEY_RE.test(keyHex)) {
		throw new PushoverEncryptionError(
			'Pushover encryption key must be exactly 64 hexadecimal characters (256 bits)',
		);
	}
	return Buffer.from(keyHex, 'hex');
}

export interface EncryptOptions {
	iv?: Buffer;
}

export function encryptField(plaintext: string, keyHex: string, options: EncryptOptions = {}): string {
	const key = parseKey(keyHex);
	const iv = options.iv ?? randomBytes(IV_LEN);
	if (iv.length !== IV_LEN) {
		throw new PushoverEncryptionError(`IV must be ${IV_LEN} bytes`);
	}

	const compressed = gzipSync(Buffer.from(plaintext, 'utf8'), { level: 9 });
	const cipher = createCipheriv('aes-256-cbc', key, iv);
	const ciphertext = Buffer.concat([cipher.update(compressed), cipher.final()]);

	const hmac = createHmac('sha256', key)
		.update(Buffer.concat([iv, ciphertext]))
		.digest();

	return Buffer.concat([iv, ciphertext, hmac]).toString('base64');
}

export function decryptField(payloadBase64: string, keyHex: string): string {
	const key = parseKey(keyHex);
	const blob = Buffer.from(payloadBase64, 'base64');
	if (blob.length < IV_LEN + HMAC_LEN + 1) {
		throw new PushoverEncryptionError('Ciphertext is too short to be a valid Pushover payload');
	}

	const iv = blob.subarray(0, IV_LEN);
	const ciphertext = blob.subarray(IV_LEN, blob.length - HMAC_LEN);
	const providedMac = blob.subarray(blob.length - HMAC_LEN);

	const expectedMac = createHmac('sha256', key)
		.update(Buffer.concat([iv, ciphertext]))
		.digest();

	if (!timingSafeEqual(expectedMac, providedMac)) {
		throw new PushoverEncryptionError('HMAC validation failed');
	}

	try {
		const decipher = createDecipheriv('aes-256-cbc', key, iv);
		const compressed = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
		return gunzipSync(compressed).toString('utf8');
	} catch (err) {
		// decipher.final() can throw on bad padding; gunzipSync can throw on
		// non-gzip bytes. Both surface as PushoverEncryptionError so callers
		// can rely on a single error type.
		throw new PushoverEncryptionError(`Decryption failed: ${(err as Error).message}`);
	}
}

export function generateKeyHex(): string {
	return randomBytes(32).toString('hex');
}
