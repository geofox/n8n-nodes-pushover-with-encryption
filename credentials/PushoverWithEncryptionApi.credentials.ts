import type {
	IAuthenticateGeneric,
	ICredentialTestRequest,
	ICredentialType,
	INodeProperties,
} from 'n8n-workflow';

// Credential for Pushover (https://pushover.net/api).
// Authentication is by application token, sent on the form body as `token`.
// An optional 64-character hexadecimal encryption key enables client-side
// field encryption per Pushover's encrypted-message specification.
export class PushoverWithEncryptionApi implements ICredentialType {
	name = 'pushoverWithEncryptionApi';

	displayName = 'Pushover (with Encryption) API';

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

	// Pushover takes the token as a form-body field on POST, or a query
	// parameter on GET. The declarative IAuthenticateGeneric covers both: body
	// for write operations and qs for read-only endpoints (e.g. sounds.json).
	authenticate: IAuthenticateGeneric = {
		type: 'generic',
		properties: {
			qs: {
				token: '={{$credentials.apiKey}}',
			},
			body: {
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
