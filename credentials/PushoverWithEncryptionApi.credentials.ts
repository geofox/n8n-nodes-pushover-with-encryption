import type {
	IAuthenticateGeneric,
	Icon,
	ICredentialTestRequest,
	ICredentialType,
	INodeProperties,
} from 'n8n-workflow';

// Credential for Pushover (https://pushover.net/api).
// Authentication is by application token. An optional 64-character
// hexadecimal encryption key enables client-side field encryption per
// Pushover's encrypted-message specification.
export class PushoverWithEncryptionApi implements ICredentialType {
	name = 'pushoverWithEncryptionApi';

	displayName = 'Pushover (with Encryption) API';

	icon: Icon = { light: 'file:../icons/pushover.svg', dark: 'file:../icons/pushover.svg' };

	documentationUrl = 'https://pushover.net/api';

	properties: INodeProperties[] = [
		{
			displayName: 'Application Token',
			name: 'apiKey',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			description: 'The application API token (APP_TOKEN) created in your Pushover dashboard',
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
			description:
				'Optional 64-character hexadecimal encryption key (256 bits). Leave empty to disable client-side encryption. The same key must be configured in your Pushover apps to decrypt incoming messages.',
		},
	];

	// Pushover accepts the token as a query parameter. That covers the GET
	// endpoints (sounds.json, the credential test below). For the multipart
	// POST to messages.json the node also appends `token` to the form body
	// itself, because n8n's generic auth cannot write into a FormData body.
	authenticate: IAuthenticateGeneric = {
		type: 'generic',
		properties: {
			qs: {
				token: '={{$credentials.apiKey}}',
			},
		},
	};

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
