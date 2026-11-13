import { createCipheriv, createDecipheriv, createHmac, randomBytes, timingSafeEqual } from 'crypto';

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
	// Trim surrounding whitespace so a trailing newline from `openssl rand
	// -hex 32` or a stray space pasted into the credential UI doesn't reject
	// an otherwise-valid key.
	const trimmed = keyHex.trim();
	if (!HEX_KEY_RE.test(trimmed)) {
		throw new PushoverEncryptionError(
			'Pushover encryption key must be exactly 64 hexadecimal characters (256 bits)',
		);
	}
	return Buffer.from(trimmed, 'hex');
}

// gzip via the WHATWG Compression Streams API (a Node.js global since v18)
// rather than `zlib`: n8n's community-node lint rules only allow `crypto`
// among Node built-ins, so this keeps the node eligible for n8n Cloud. The
// output is a standard RFC 1952 gzip stream, which is all Pushover's spec
// and its apps require; the compression level is zlib's default.
async function pipeThrough(data: Uint8Array, transform: CompressionStream | DecompressionStream) {
	const stream = new Blob([data]).stream().pipeThrough(transform);
	return Buffer.from(await new Response(stream).arrayBuffer());
}

const gzip = async (data: Uint8Array) => await pipeThrough(data, new CompressionStream('gzip'));
const gunzip = async (data: Uint8Array) => await pipeThrough(data, new DecompressionStream('gzip'));

export interface EncryptOptions {
	iv?: Buffer;
}

export async function encryptField(
	plaintext: string,
	keyHex: string,
	options: EncryptOptions = {},
): Promise<string> {
	const key = parseKey(keyHex);
	const iv = options.iv ?? randomBytes(IV_LEN);
	if (iv.length !== IV_LEN) {
		throw new PushoverEncryptionError(`IV must be ${IV_LEN} bytes`);
	}

	const compressed = await gzip(Buffer.from(plaintext, 'utf8'));
	const cipher = createCipheriv('aes-256-cbc', key, iv);
	const ciphertext = Buffer.concat([cipher.update(compressed), cipher.final()]);

	const hmac = createHmac('sha256', key)
		.update(Buffer.concat([iv, ciphertext]))
		.digest();

	return Buffer.concat([iv, ciphertext, hmac]).toString('base64');
}

async function decipherAndGunzip(key: Buffer, iv: Buffer, ciphertext: Buffer): Promise<string> {
	const decipher = createDecipheriv('aes-256-cbc', key, iv);
	const compressed = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
	return (await gunzip(compressed)).toString('utf8');
}

// Inverse of encryptField. The node itself never decrypts; this is the
// round-trip helper the test suite uses to prove the encryption is correct
// and interoperable with the reference OpenSSL + gzip pipeline.
export async function decryptField(payloadBase64: string, keyHex: string): Promise<string> {
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

	// decipher.final() rejects bad padding and gunzip rejects non-gzip bytes.
	// Both surface as PushoverEncryptionError so callers can rely on a single
	// error type.
	return await decipherAndGunzip(key, iv, ciphertext).catch((error: unknown) => {
		const reason = error instanceof Error ? error.message : String(error);
		throw new PushoverEncryptionError(`Decryption failed: ${reason}`);
	});
}

export function generateKeyHex(): string {
	return randomBytes(32).toString('hex');
}
