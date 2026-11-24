import type {
	IExecuteFunctions,
	IHttpRequestOptions,
	ILoadOptionsFunctions,
	INode,
} from 'n8n-workflow';
import { NodeApiError, NodeOperationError } from 'n8n-workflow';

import { PushoverWithEncryptionApi } from '../credentials/PushoverWithEncryptionApi.credentials';
import { decryptField } from '../nodes/Pushover/encryption';
import { PushoverWithEncryption } from '../nodes/Pushover/PushoverWithEncryption.node';
import { CREDENTIAL_NAME, toMultipartBody } from '../nodes/Pushover/pushoverClient';

const KEY = 'b'.repeat(64);
const TOKEN = 'app-token-123';
const ALL_FIELDS = ['message', 'title', 'url', 'url_title'];
const NODE: INode = {
	id: 'node-1',
	name: 'Pushover (with Encryption)',
	type: 'pushoverWithEncryption',
	typeVersion: 1,
	position: [0, 0],
	parameters: {},
};

interface FakeResponse {
	statusCode: number;
	body: unknown;
}

interface ContextOptions {
	params?: Record<string, unknown>;
	credentials?: Record<string, unknown>;
	continueOnFail?: boolean;
	items?: number;
	response?: unknown;
	statusCode?: number;
	// One response per request, in order; overrides response/statusCode.
	responses?: FakeResponse[];
	requestError?: Error;
}

function makeContext(options: ContextOptions = {}) {
	const params: Record<string, unknown> = {
		userKey: 'user-key-abc',
		message: 'hello',
		priority: 0,
		encryptFields: [],
		optionalFields: {},
		...options.params,
	};
	let call = 0;
	const httpRequestWithAuthentication = jest.fn(async () => {
		if (options.requestError) throw options.requestError;
		// The node asks for the full response with HTTP errors returned, not thrown.
		const scripted = options.responses?.[call++];
		return {
			statusCode: scripted?.statusCode ?? options.statusCode ?? 200,
			headers: {},
			body: scripted?.body ?? options.response ?? { status: 1, request: 'req-1' },
		};
	});
	const getCredentials = jest.fn(async () => ({
		apiKey: TOKEN,
		encryptionKey: KEY,
		...options.credentials,
	}));
	const context = {
		getInputData: () => Array.from({ length: options.items ?? 1 }, () => ({ json: {} })),
		getNodeParameter: (name: string, _i: number, fallback?: unknown) =>
			// Fresh copies, as n8n returns them, so the node can mutate safely.
			structuredClone(name in params ? params[name] : fallback),
		getCredentials,
		getNode: () => NODE,
		continueOnFail: () => options.continueOnFail ?? false,
		helpers: {
			httpRequestWithAuthentication,
			assertBinaryData: jest.fn(() => ({
				data: '',
				mimeType: 'image/png',
				fileName: 'photo.png',
			})),
			getBinaryDataBuffer: jest.fn(async () => Buffer.from([0x89, 0x50, 0x4e, 0x47])),
			returnJsonArray: (data: object | object[]) =>
				(Array.isArray(data) ? data : [data]).map((json) => ({ json })),
			constructExecutionMetaData: (items: object[], { itemData }: { itemData: object }) =>
				items.map((item) => ({ ...item, pairedItem: itemData })),
		},
	};
	return {
		context: context as unknown as IExecuteFunctions,
		httpRequestWithAuthentication,
		getCredentials,
	};
}

function sentRequest(mock: jest.Mock, call = 0) {
	const [credentialName, options] = mock.mock.calls[call] as [string, IHttpRequestOptions];
	return { credentialName, options, form: options.body as unknown as FormData };
}

const execute = async (context: IExecuteFunctions) =>
	await new PushoverWithEncryption().execute.call(context);

const failure = async (context: IExecuteFunctions) =>
	await execute(context).then(
		() => {
			throw new Error('expected the node to fail');
		},
		(error: unknown) => error as NodeOperationError,
	);

describe('PushoverWithEncryption node', () => {
	test('POSTs a multipart body through httpRequestWithAuthentication', async () => {
		const { context, httpRequestWithAuthentication } = makeContext();

		const result = await execute(context);

		expect(result).toEqual([[{ json: { status: 1, request: 'req-1' }, pairedItem: { item: 0 } }]]);
		const { credentialName, options, form } = sentRequest(httpRequestWithAuthentication);
		expect(credentialName).toBe(CREDENTIAL_NAME);
		expect(options).toEqual({
			method: 'POST',
			url: 'https://api.pushover.net/1/messages.json',
			json: true,
			ignoreHttpStatusErrors: true,
			returnFullResponse: true,
			body: expect.any(FormData),
		});
		// axios must generate the multipart Content-Type (with its boundary),
		// and the token is added by the credential, not by the node.
		expect(options.headers).toBeUndefined();
		expect(options.qs).toBeUndefined();
		expect(Object.fromEntries(form)).toEqual({
			user: 'user-key-abc',
			message: 'hello',
			priority: '0',
		});
	});

	test('does not read the credential when nothing is to be encrypted', async () => {
		const { context, getCredentials } = makeContext();

		await execute(context);

		expect(getCredentials).not.toHaveBeenCalled();
	});

	test('encrypts the selected fields and flags the message as encrypted', async () => {
		const { context, httpRequestWithAuthentication } = makeContext({
			params: {
				encryptFields: ALL_FIELDS,
				optionalFields: {
					title: 'Disk alert',
					url: 'https://grafana.example.com/d/1',
					url_title: 'Open dashboard',
				},
			},
		});

		await execute(context);

		const { form } = sentRequest(httpRequestWithAuthentication);
		expect(form.get('encrypted')).toBe('1');
		await expect(decryptField(form.get('message') as string, KEY)).resolves.toBe('hello');
		await expect(decryptField(form.get('title') as string, KEY)).resolves.toBe('Disk alert');
		await expect(decryptField(form.get('url') as string, KEY)).resolves.toBe(
			'https://grafana.example.com/d/1',
		);
		await expect(decryptField(form.get('url_title') as string, KEY)).resolves.toBe(
			'Open dashboard',
		);
		expect(form.get('user')).toBe('user-key-abc');
	});

	test('encrypts only the selected fields', async () => {
		const { context, httpRequestWithAuthentication } = makeContext({
			params: {
				encryptFields: ['message'],
				optionalFields: { title: 'Disk alert' },
			},
		});

		await execute(context);

		const { form } = sentRequest(httpRequestWithAuthentication);
		await expect(decryptField(form.get('message') as string, KEY)).resolves.toBe('hello');
		expect(form.get('title')).toBe('Disk alert');
		expect(form.get('encrypted')).toBe('1');
	});

	test('encrypts values that are not strings, such as a number from an expression', async () => {
		const { context, httpRequestWithAuthentication } = makeContext({
			params: { message: 21.5, encryptFields: ['message', 'title'], optionalFields: { title: 7 } },
		});

		await execute(context);

		const { form } = sentRequest(httpRequestWithAuthentication);
		await expect(decryptField(form.get('message') as string, KEY)).resolves.toBe('21.5');
		await expect(decryptField(form.get('title') as string, KEY)).resolves.toBe('7');
		expect(form.get('encrypted')).toBe('1');
	});

	test('gives an encrypted message without a title an encrypted fallback title', async () => {
		// Left out, Pushover would add the app name in plaintext, which the apps
		// then fail to decrypt.
		const { context, httpRequestWithAuthentication } = makeContext({
			params: { encryptFields: ALL_FIELDS },
		});

		await execute(context);

		const { form } = sentRequest(httpRequestWithAuthentication);
		await expect(decryptField(form.get('title') as string, KEY)).resolves.toBe('n8n');
		expect(form.has('url')).toBe(false);
		expect(form.has('url_title')).toBe(false);
	});

	test('adds no title when the title is not to be encrypted', async () => {
		const { context, httpRequestWithAuthentication } = makeContext({
			params: { encryptFields: ['message'] },
		});

		await execute(context);

		expect(sentRequest(httpRequestWithAuthentication).form.has('title')).toBe(false);
	});

	test('accepts Encrypt Fields as a comma-separated string from an expression', async () => {
		const { context, httpRequestWithAuthentication } = makeContext({
			params: { encryptFields: ' message, title ', optionalFields: { title: 'T' } },
		});

		await execute(context);

		const { form } = sentRequest(httpRequestWithAuthentication);
		await expect(decryptField(form.get('message') as string, KEY)).resolves.toBe('hello');
		await expect(decryptField(form.get('title') as string, KEY)).resolves.toBe('T');
	});

	test.each([
		[['user', 'token', 'priority']],
		[['Message']],
		[['message', 'body']],
		[42],
		[{ message: true }],
	])(
		'refuses unsupported Encrypt Fields %j instead of sending plaintext',
		async (encryptFields) => {
			const { context, httpRequestWithAuthentication } = makeContext({
				params: { encryptFields },
			});

			const error = await failure(context);

			expect(error).toBeInstanceOf(NodeOperationError);
			expect(error.message).toMatch(/'Encrypt Fields' contains unsupported values/);
			expect(error.context.itemIndex).toBe(0);
			expect(httpRequestWithAuthentication).not.toHaveBeenCalled();
		},
	);

	test('fails the item with a clear error when encryption is requested without a key', async () => {
		const { context, httpRequestWithAuthentication } = makeContext({
			params: { encryptFields: ['message'] },
			credentials: { encryptionKey: '' },
		});

		const error = await failure(context);

		expect(error).toBeInstanceOf(NodeOperationError);
		expect(error.message).toBe('The credential has no encryption key');
		expect(error.description).toMatch(/'Encryption Key \(Hex\)' is empty/);
		expect(error.context.itemIndex).toBe(0);
		expect(httpRequestWithAuthentication).not.toHaveBeenCalled();
	});

	test('fails the item with a clear error when the key is not 64 hex characters', async () => {
		const { context, httpRequestWithAuthentication } = makeContext({
			params: { encryptFields: ['message'] },
			credentials: { encryptionKey: 'not-a-key' },
		});

		const error = await failure(context);

		expect(error.message).toBe("The credential's encryption key is not valid");
		expect(error.description).toMatch(/64 hexadecimal characters/);
		expect(httpRequestWithAuthentication).not.toHaveBeenCalled();
	});

	test('reads only known optional fields, so they cannot override other form fields', async () => {
		const { context, httpRequestWithAuthentication } = makeContext({
			params: {
				optionalFields: JSON.parse(
					'{"user":"someone-else","encrypted":"1","token":"x","priority":2,"__proto__":{"a":1},"device":"phone"}',
				),
			},
		});

		await execute(context);

		expect(Object.fromEntries(sentRequest(httpRequestWithAuthentication).form)).toEqual({
			user: 'user-key-abc',
			message: 'hello',
			priority: '0',
			device: 'phone',
		});
	});

	test('leaves out empty optional fields', async () => {
		const { context, httpRequestWithAuthentication } = makeContext({
			params: {
				optionalFields: { title: '', url: '', url_title: '', device: '', sound: '', ttl: 0 },
			},
		});

		await execute(context);

		expect([...sentRequest(httpRequestWithAuthentication).form.keys()]).toEqual([
			'user',
			'message',
			'priority',
		]);
	});

	test('sends a positive TTL as whole seconds', async () => {
		const { context, httpRequestWithAuthentication } = makeContext({
			params: { optionalFields: { ttl: 3600.9 } },
		});

		await execute(context);

		expect(sentRequest(httpRequestWithAuthentication).form.get('ttl')).toBe('3600');
	});

	test.each([[-5], ['soon']])('refuses an unusable TTL (%j)', async (ttl) => {
		const { context, httpRequestWithAuthentication } = makeContext({
			params: { optionalFields: { ttl } },
		});

		const error = await failure(context);

		expect(error.message).toMatch(/'TTL \(Seconds\)' is not a valid duration/);
		expect(httpRequestWithAuthentication).not.toHaveBeenCalled();
	});

	test.each([[''], [null]])('refuses an empty message (%j) without calling Pushover', async (m) => {
		const { context, httpRequestWithAuthentication } = makeContext({ params: { message: m } });

		const error = await failure(context);

		expect(error.message).toBe("'Message' is empty");
		expect(httpRequestWithAuthentication).not.toHaveBeenCalled();
	});

	test.each([[5], ['high'], [1.5]])('refuses an invalid priority (%j)', async (priority) => {
		const { context, httpRequestWithAuthentication } = makeContext({ params: { priority } });

		const error = await failure(context);

		expect(error.message).toMatch(/'Priority' must be/);
		expect(httpRequestWithAuthentication).not.toHaveBeenCalled();
	});

	test('attaches binary data as a named, typed file part', async () => {
		const { context, httpRequestWithAuthentication } = makeContext({
			params: {
				optionalFields: { attachmentsUi: { attachment: { binaryPropertyName: 'data' } } },
			},
		});

		await execute(context);

		const { form } = sentRequest(httpRequestWithAuthentication);
		const file = form.get('attachment') as File;
		expect(file).toBeInstanceOf(Blob);
		expect(file.name).toBe('photo.png');
		expect(file.type).toBe('image/png');
		expect(Buffer.from(await file.arrayBuffer())).toEqual(Buffer.from([0x89, 0x50, 0x4e, 0x47]));
		expect(form.has('attachmentsUi')).toBe(false);
	});

	test('converts an ISO timestamp to Unix seconds and HTML to the "1" flag', async () => {
		const { context, httpRequestWithAuthentication } = makeContext({
			params: { optionalFields: { timestamp: '2026-11-13T12:00:00.000Z', html: true } },
		});

		await execute(context);

		const { form } = sentRequest(httpRequestWithAuthentication);
		expect(form.get('timestamp')).toBe(String(Date.UTC(2026, 10, 13, 12) / 1000));
		expect(form.get('html')).toBe('1');
	});

	test('keeps a Unix timestamp and rejects an unparseable one', async () => {
		const ok = makeContext({ params: { optionalFields: { timestamp: '1763035200' } } });
		await execute(ok.context);
		expect(sentRequest(ok.httpRequestWithAuthentication).form.get('timestamp')).toBe('1763035200');

		const bad = makeContext({ params: { optionalFields: { timestamp: 'yesterday-ish' } } });
		expect((await failure(bad.context)).message).toMatch(/'Timestamp' is not a valid date/);
	});

	test('sends retry and expire for emergency priority', async () => {
		const { context, httpRequestWithAuthentication } = makeContext({
			params: { priority: '2', retry: 60, expire: 3600 },
		});

		await execute(context);

		const { form } = sentRequest(httpRequestWithAuthentication);
		expect(form.get('priority')).toBe('2');
		expect(form.get('retry')).toBe('60');
		expect(form.get('expire')).toBe('3600');
	});

	test('rethrows API errors unchanged, tagged with the failing item', async () => {
		const apiError = new NodeApiError(NODE, { message: 'user identifier is invalid' });
		const { context } = makeContext({ requestError: apiError });

		const error = await execute(context).catch((e: unknown) => e);

		expect(error).toBe(apiError);
		expect(apiError.context.itemIndex).toBe(0);
	});

	test("reports Pushover's own error text for a rejected request", async () => {
		const { context } = makeContext({
			statusCode: 400,
			response: { user: 'invalid', errors: ['user identifier is invalid'], status: 0 },
		});

		const error = await execute(context).catch((e: unknown) => e);

		expect(error).toBeInstanceOf(NodeApiError);
		expect(error).toMatchObject({
			httpCode: '400',
			message: 'Bad request - please check your parameters',
			description: 'user identifier is invalid',
		});
		expect((error as NodeApiError).context.itemIndex).toBe(0);
	});

	test('fails with the HTTP status when the error body is not JSON', async () => {
		const { context } = makeContext({ statusCode: 502, response: '<html>Bad Gateway</html>' });

		const error = await execute(context).catch((e: unknown) => e);

		expect(error).toBeInstanceOf(NodeApiError);
		expect((error as NodeApiError).httpCode).toBe('502');
	});

	test('reports the error on the item and continues when "Continue On Fail" is set', async () => {
		const { context, httpRequestWithAuthentication } = makeContext({
			continueOnFail: true,
			items: 2,
			requestError: new Error('network down'),
		});

		const result = await execute(context);

		expect(httpRequestWithAuthentication).toHaveBeenCalledTimes(2);
		expect(result).toEqual([
			[
				{ json: { error: 'network down' }, pairedItem: { item: 0 } },
				{ json: { error: 'network down' }, pairedItem: { item: 1 } },
			],
		]);
	});

	test("keeps Pushover's explanation in the item when continuing on fail", async () => {
		const rejected = {
			statusCode: 400,
			body: { user: 'invalid', errors: ['user identifier is invalid'], status: 0 },
		};
		const { context, httpRequestWithAuthentication } = makeContext({
			continueOnFail: true,
			items: 2,
			responses: [rejected, rejected],
		});

		const [items] = await execute(context);

		// A per-recipient problem does not stop the other items.
		expect(httpRequestWithAuthentication).toHaveBeenCalledTimes(2);
		expect(items[0].json).toEqual({
			error: 'Bad request - please check your parameters',
			description: 'user identifier is invalid',
		});
	});

	test.each([
		[
			'the quota is used up (429)',
			{ statusCode: 429, body: { errors: ['over quota'], status: 0 } },
		],
		[
			'the application token is refused',
			{ statusCode: 400, body: { token: 'invalid', errors: ['application token is invalid'] } },
		],
	])('stops contacting Pushover once %s', async (_label, refusal) => {
		const { context, httpRequestWithAuthentication } = makeContext({
			continueOnFail: true,
			items: 3,
			responses: [{ statusCode: 200, body: { status: 1, request: 'ok' } }, refusal],
		});

		const [items] = await execute(context);

		expect(httpRequestWithAuthentication).toHaveBeenCalledTimes(2);
		expect(items).toHaveLength(3);
		expect(items[0].json).toEqual({ status: 1, request: 'ok' });
		expect(items[2].pairedItem).toEqual({ item: 2 });
		expect(items[2].json.error).toMatch(/^Not sent: Pushover refused item 1 for the whole account/);
		expect(items[2].json.description).toMatch(/stopped sending/);
	});

	test('loads the sound list with an authenticated GET and no body', async () => {
		const { context, httpRequestWithAuthentication } = makeContext({
			response: { sounds: { pushover: 'Pushover (default)', bike: 'Bike' }, status: 1 },
		});

		const options = await new PushoverWithEncryption().methods.loadOptions.getSounds.call(
			context as unknown as ILoadOptionsFunctions,
		);

		expect(options).toEqual([
			{ name: 'Pushover (default)', value: 'pushover' },
			{ name: 'Bike', value: 'bike' },
		]);
		const { credentialName, options: request } = sentRequest(httpRequestWithAuthentication);
		expect(credentialName).toBe(CREDENTIAL_NAME);
		expect(request).toEqual({
			method: 'GET',
			url: 'https://api.pushover.net/1/sounds.json',
			json: true,
			ignoreHttpStatusErrors: true,
			returnFullResponse: true,
		});
	});
});

describe('PushoverWithEncryptionApi credential', () => {
	const credential = new PushoverWithEncryptionApi();

	test('puts the token in the multipart body of a POST, not in the URL', async () => {
		const form = toMultipartBody({ user: 'u', message: 'm' });
		const options: IHttpRequestOptions = { method: 'POST', url: 'https://x', body: form };

		const result = await credential.authenticate({ apiKey: ` ${TOKEN}\n` }, options);

		expect(result.qs).toBeUndefined();
		expect((result.body as FormData).getAll('token')).toEqual([TOKEN]);
	});

	test('replaces a token already in the form instead of sending two', async () => {
		const form = new FormData();
		form.append('token', 'stale');

		await credential.authenticate({ apiKey: TOKEN }, { url: 'https://x', body: form });

		expect(form.getAll('token')).toEqual([TOKEN]);
	});

	test('puts the token in the query string of a GET, keeping other parameters', async () => {
		const options: IHttpRequestOptions = { method: 'GET', url: 'https://x', qs: { a: 1 } };

		const result = await credential.authenticate({ apiKey: TOKEN }, options);

		expect(result.qs).toEqual({ a: 1, token: TOKEN });
		expect(options.qs).toEqual({ a: 1 });
	});

	test('is restricted to the nodes of this package', () => {
		expect(credential.restrictToSupportedNodes).toBe(true);
	});
});

describe('toMultipartBody', () => {
	test('stringifies scalars, skips null/undefined and adds no token', () => {
		const form = toMultipartBody({ a: 1, b: 'x', c: undefined, d: null, e: '' });

		expect([...form.entries()]).toEqual([
			['a', '1'],
			['b', 'x'],
			['e', ''],
		]);
	});

	test('falls back to a generic file name and type for bare binary data', () => {
		const form = toMultipartBody({}, { data: Buffer.from('x') });

		const file = form.get('attachment') as File;
		expect(file.name).toBe('attachment');
		expect(file.type).toBe('application/octet-stream');
	});
});
