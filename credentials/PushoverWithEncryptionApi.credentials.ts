import type {
	ICredentialDataDecryptedObject,
	ICredentialTestRequest,
	ICredentialType,
	IHttpRequestOptions,
	Icon,
	INodeProperties,
} from 'n8n-workflow';

// A multipart body built by the node. `instanceof FormData` would work too,
// but the tag check does not depend on which realm created the object.
const isFormData = (body: unknown): body is FormData =>
	Object.prototype.toString.call(body) === '[object FormData]';

// Credential for Pushover (https://pushover.net/api).
// Authentication is by application token. An optional 64-character
// hexadecimal encryption key enables Pushover's end-to-end encryption
// (https://pushover.net/api#e2ee) of the message, title, url and url_title.
export class PushoverWithEncryptionApi implements ICredentialType {
	name = 'pushoverWithEncryptionApi';

	displayName = 'Pushover (with Encryption) API';

	icon: Icon = { light: 'file:../icons/pushover.svg', dark: 'file:../icons/pushover.svg' };

	documentationUrl = 'https://pushover.net/api';

	// This credential holds the end-to-end encryption key, so only this
	// package's node (and its AI tool variant, which n8n registers
	// automatically) may use it. Without this, anyone allowed to use a shared
	// credential could select it in the HTTP Request node and point a request
	// at their own server. n8n versions that predate the flag ignore it.
	restrictToSupportedNodes = true as const;

	properties: INodeProperties[] = [
		{
			displayName: 'Application Token',
			name: 'apiKey',
			type: 'string',
			typeOptions: { password: true },
			required: true,
			default: '',
			description:
				'The API token of the application you created on the Pushover dashboard (pushover.net/apps/build)',
		},
		// The lint heuristic judges secrecy by field name only. This is an
		// AES-256 / HMAC key, so it must stay masked; renaming the field would
		// orphan the key stored in every existing credential.
		// eslint-disable-next-line @n8n/community-nodes/credential-unnecessary-password
		{
			displayName: 'Encryption Key (Hex)',
			name: 'encryptionKey',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			hint: 'Generate a key with: openssl rand -hex 32',
			description:
				'Optional 256-bit end-to-end encryption key, as 64 hexadecimal characters. Configure the same key in every Pushover app that should decrypt your messages. Leave empty to send plaintext only.',
		},
	];

	// Pushover reads `token` from the query string or the body. The GET
	// endpoints (sounds.json, the credential test below) take it as a query
	// parameter. The node sends messages as a multipart/form-data POST, and
	// for that the token goes into the form body only, so it does not end up
	// in the request URL, where proxies and logs tend to record it. A generic
	// `body` rule cannot do this: n8n would set a plain property on the
	// FormData object, which is never serialized.
	async authenticate(
		credentials: ICredentialDataDecryptedObject,
		requestOptions: IHttpRequestOptions,
	): Promise<IHttpRequestOptions> {
		const token = String(credentials.apiKey ?? '').trim();
		if (isFormData(requestOptions.body)) {
			requestOptions.body.set('token', token);
			return requestOptions;
		}
		return { ...requestOptions, qs: { ...requestOptions.qs, token } };
	}

	// The /1/sounds.json endpoint is a cheap GET that requires only a valid
	// application token. It returns the sound catalogue, so it doubles as both
	// a credential check and the lookup the node uses to populate the Sound
	// dropdown.
	test: ICredentialTestRequest = {
		request: {
			baseURL: 'https://api.pushover.net/1',
			url: '/sounds.json',
			method: 'GET',
		},
	};
}
