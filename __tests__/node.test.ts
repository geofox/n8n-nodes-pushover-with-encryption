import type {
	IExecuteFunctions,
	IHttpRequestOptions,
	ILoadOptionsFunctions,
	INode,
} from 'n8n-workflow';
import { NodeApiError, NodeOperationError } from 'n8n-workflow';

import { decryptField } from '../nodes/Pushover/encryption';
import { PushoverWithEncryption } from '../nodes/Pushover/PushoverWithEncryption.node';
import { CREDENTIAL_NAME, toMultipartBody } from '../nodes/Pushover/pushoverClient';

const KEY = 'b'.repeat(64);
const TOKEN = 'app-token-123';
const NODE: INode = {
	id: 'node-1',
	name: 'Pushover (with Encryption)',
	type: 'pushoverWithEncryption',
	typeVersion: 1,
	position: [0, 0],
	parameters: {},
};

interface ContextOptions {
	params?: Record<string, unknown>;
	credentials?: Record<string, unknown>;
	continueOnFail?: boolean;
	items?: number;
	response?: unknown;
	statusCode?: number;
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
	const httpRequestWithAuthentication = jest.fn(async () => {
		if (options.requestError) throw options.requestError;
		// The node asks for the full response with HTTP errors returned, not thrown.
		return {
			statusCode: options.statusCode ?? 200,
			headers: {},
			body: options.response ?? { status: 1, request: 'req-1' },
		};
	});
	const context = {
		getInputData: () => Array.from({ length: options.items ?? 1 }, () => ({ json: {} })),
		getNodeParameter: (name: string, _i: number, fallback?: unknown) =>
			// Fresh copies, as n8n returns them, so the node can mutate safely.
			structuredClone(name in params ? params[name] : fallback),
		getCredentials: jest.fn(async () => ({
			apiKey: TOKEN,
			encryptionKey: KEY,
			...options.credentials,
		})),
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
	return { context: context as unknown as IExecuteFunctions, httpRequestWithAuthentication };
}

function sentRequest(mock: jest.Mock, call = 0) {
	const [credentialName, options] = mock.mock.calls[call] as [string, IHttpRequestOptions];
	return { credentialName, options, form: options.body as unknown as FormData };
}

const execute = async (context: IExecuteFunctions) =>
	await new PushoverWithEncryption().execute.call(context);

describe('PushoverWithEncryption node', () => {
	test('POSTs a multipart body through httpRequestWithAuthentication', async () => {
		const { context, httpRequestWithAuthentication } = makeContext();

		const result = await execute(context);

		expect(result).toEqual([[{ json: { status: 1, request: 'req-1' }, pairedItem: { item: 0 } }]]);
		const { credentialName, options, form } = sentRequest(httpRequestWithAuthentication);
		expect(credentialName).toBe(CREDENTIAL_NAME);
		expect(options).toMatchObject({
			method: 'POST',
			url: 'https://api.pushover.net/1/messages.json',
			json: true,
			ignoreHttpStatusErrors: true,
			returnFullResponse: true,
		});
		// axios must generate the multipart Content-Type (with its boundary).
		expect(options.headers).toBeUndefined();
		expect(form).toBeInstanceOf(FormData);
		expect(Object.fromEntries(form)).toEqual({
			user: 'user-key-abc',
			message: 'hello',
			priority: '0',
			token: TOKEN,
		});
	});

	test('encrypts the selected fields and flags the message as encrypted', async () => {
		const { context, httpRequestWithAuthentication } = makeContext({
			params: {
				encryptFields: ['message', 'title'],
				optionalFields: { title: 'Disk alert', url_title: 'Open dashboard' },
			},
		});

		await execute(context);

		const { form } = sentRequest(httpRequestWithAuthentication);
		expect(form.get('encrypted')).toBe('1');
		await expect(decryptField(form.get('message') as string, KEY)).resolves.toBe('hello');
		await expect(decryptField(form.get('title') as string, KEY)).resolves.toBe('Disk alert');
		expect(form.get('url_title')).toBe('Open dashboard');
		expect(form.get('user')).toBe('user-key-abc');
	});

	test('ignores non-encryptable names supplied to Encrypt Fields by an expression', async () => {
		const { context, httpRequestWithAuthentication } = makeContext({
			params: { encryptFields: ['user', 'token', 'priority'] },
		});

		await execute(context);

		const { form } = sentRequest(httpRequestWithAuthentication);
		expect(form.get('user')).toBe('user-key-abc');
		expect(form.get('priority')).toBe('0');
		expect(form.get('encrypted')).toBeNull();
	});

	test('fails the item with a clear error when encryption is requested without a key', async () => {
		const { context, httpRequestWithAuthentication } = makeContext({
			params: { encryptFields: ['message'] },
			credentials: { encryptionKey: '' },
		});

		const error = await execute(context).catch((e: unknown) => e);

		expect(error).toBeInstanceOf(NodeOperationError);
		expect((error as NodeOperationError).message).toMatch(/no Encryption Key is set/);
		expect((error as NodeOperationError).context.itemIndex).toBe(0);
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

	test('sends retry and expire for emergency priority', async () => {
		const { context, httpRequestWithAuthentication } = makeContext({
			params: { priority: 2, retry: 60, expire: 3600 },
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

describe('toMultipartBody', () => {
	test('stringifies scalars, skips null/undefined and appends the token last', () => {
		const form = toMultipartBody({ a: 1, b: 'x', c: undefined, d: null, e: '' }, 't');

		expect([...form.entries()]).toEqual([
			['a', '1'],
			['b', 'x'],
			['e', ''],
			['token', 't'],
		]);
	});

	test('falls back to a generic file name and type for bare binary data', () => {
		const form = toMultipartBody({}, 't', { data: Buffer.from('x') });

		const file = form.get('attachment') as File;
		expect(file.name).toBe('attachment');
		expect(file.type).toBe('application/octet-stream');
	});
});
