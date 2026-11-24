import type {
	IDataObject,
	IExecuteFunctions,
	ILoadOptionsFunctions,
	INode,
	INodeExecutionData,
	INodePropertyOptions,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';
import { NodeApiError, NodeConnectionTypes, NodeOperationError } from 'n8n-workflow';

import { encryptField, isValidKeyHex } from './encryption';
import type { PushoverAttachment } from './pushoverClient';
import { CREDENTIAL_NAME, isAccountLevelError, listSounds, sendMessage } from './pushoverClient';

// The text fields Pushover's end-to-end encryption covers
// (https://pushover.net/api#e2ee). Everything else, attachments included,
// always travels in plaintext.
const ENCRYPTABLE_FIELDS = ['message', 'title', 'url', 'url_title'] as const;
type EncryptableField = (typeof ENCRYPTABLE_FIELDS)[number];

const isEncryptableField = (value: unknown): value is EncryptableField =>
	(ENCRYPTABLE_FIELDS as readonly unknown[]).includes(value);

// Optional text fields copied from the 'Optional Fields' collection. The
// collection is read through this list, never merged wholesale, so a crafted
// workflow cannot inject or override other form fields (user, encrypted, …).
const OPTIONAL_TEXT_FIELDS = ['device', 'sound', 'title', 'url', 'url_title'] as const;

// Sent, encrypted, as the title of an encrypted message that has none. Left
// empty, Pushover would fill in the application name in plaintext, which the
// apps then try, and fail, to decrypt.
const ENCRYPTED_TITLE_FALLBACK = 'n8n';

interface PushoverCredentials {
	apiKey: string;
	encryptionKey?: string;
}

interface PushoverMessage {
	fields: IDataObject;
	attachment?: PushoverAttachment;
}

// Pushover priority levels are documented as integers from -2 to 2 with
// specific semantics. We keep the semantic ordering rather than the lint
// plugin's preferred alphabetical sort.
const PRIORITY_OPTIONS = [
	{ name: 'Silent (-2, No Notification)', value: -2 },
	{ name: 'Quiet (-1)', value: -1 },
	{ name: 'Normal (0)', value: 0 },
	{ name: 'High (1, Bypasses Quiet Hours)', value: 1 },
	{ name: 'Emergency (2, Requires User Acknowledgement)', value: 2 },
];

export class PushoverWithEncryption implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Pushover (with Encryption)',
		name: 'pushoverWithEncryption',
		// The mark is a solid disc with a white glyph, so one file reads well
		// on both the light and the dark canvas.
		icon: { light: 'file:../../icons/pushover.svg', dark: 'file:../../icons/pushover.svg' },
		group: ['output'],
		version: 1,
		// Shows on the canvas whether the node encrypts, without opening it.
		subtitle:
			'={{ ($parameter["encryptFields"] || []).length ? "Send encrypted message" : "Send message (not encrypted)" }}',
		description:
			'Send Pushover notifications with optional end-to-end encryption (AES-256-CBC + HMAC-SHA256)',
		defaults: {
			name: 'Pushover (with Encryption)',
		},
		usableAsTool: true,
		inputs: [NodeConnectionTypes.Main],
		outputs: [NodeConnectionTypes.Main],
		credentials: [
			{
				name: CREDENTIAL_NAME,
				required: true,
			},
		],
		properties: [
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Send Message',
						value: 'sendMessage',
						action: 'Send a notification message',
					},
				],
				default: 'sendMessage',
			},
			{
				displayName: 'User or Group Key',
				name: 'userKey',
				type: 'string',
				required: true,
				typeOptions: { password: true },
				default: '',
				placeholder: 'e.g. uQiRzpo4DXghDmr9QzzfQu27cmVRsG',
				description:
					'Key of the recipient user or group, from the Pushover dashboard. It is never encrypted: Pushover needs it to deliver the message.',
				displayOptions: {
					show: {
						operation: ['sendMessage'],
					},
				},
			},
			{
				displayName: 'Message',
				name: 'message',
				type: 'string',
				typeOptions: { rows: 3 },
				required: true,
				default: '',
				description: 'Text of the notification, up to 1024 characters',
				displayOptions: {
					show: {
						operation: ['sendMessage'],
					},
				},
			},
			{
				displayName: 'Priority',
				name: 'priority',
				type: 'options',
				options: PRIORITY_OPTIONS,
				default: 0,
				description: 'Pushover priority level. Emergency (2) requires Retry and Expire to be set.',
				displayOptions: {
					show: {
						operation: ['sendMessage'],
					},
				},
			},
			{
				displayName: 'Retry (Seconds)',
				name: 'retry',
				type: 'number',
				typeOptions: { minValue: 30 },
				required: true,
				default: 30,
				description:
					'How often Pushover repeats the notification until it is acknowledged (at least 30)',
				displayOptions: {
					show: {
						operation: ['sendMessage'],
						priority: [2],
					},
				},
			},
			{
				displayName: 'Expire (Seconds)',
				name: 'expire',
				type: 'number',
				typeOptions: { minValue: 0, maxValue: 10800 },
				required: true,
				default: 1800,
				description:
					'How long Pushover keeps repeating an unacknowledged notification (at most 10800, 3 hours)',
				displayOptions: {
					show: {
						operation: ['sendMessage'],
						priority: [2],
					},
				},
			},
			{
				displayName: 'Encrypt Fields',
				name: 'encryptFields',
				type: 'multiOptions',
				options: [
					{ name: 'Message', value: 'message' },
					{ name: 'Title', value: 'title' },
					{ name: 'URL', value: 'url' },
					{ name: 'URL Title', value: 'url_title' },
				],
				default: ['message', 'title', 'url', 'url_title'],
				description:
					"Fields to encrypt end-to-end with the credential's Encryption Key. Pushover treats the message, title, URL and URL title of an encrypted message as encrypted, so keep all four selected: a field sent in plaintext next to encrypted ones may not display correctly. Deselect all four to send an unencrypted message.",
				hint: "Uses the credential's 'Encryption Key (Hex)'. All other fields and attachments are sent unencrypted.",
				displayOptions: {
					show: {
						operation: ['sendMessage'],
					},
				},
			},
			{
				displayName: 'Optional Fields',
				name: 'optionalFields',
				type: 'collection',
				placeholder: 'Add Field',
				default: {},
				options: [
					{
						displayName: 'Attachment (Binary)',
						name: 'attachmentsUi',
						placeholder: 'Add Attachment',
						type: 'fixedCollection',
						typeOptions: { multipleValues: false },
						default: {},
						description: 'An image to attach. Attachments are not encrypted.',
						options: [
							{
								name: 'attachment',
								displayName: 'Attachment',
								values: [
									{
										displayName: 'Input Binary Field',
										name: 'binaryPropertyName',
										type: 'string',
										default: 'data',
										description: 'Name of the input binary property holding the file to attach',
									},
								],
							},
						],
					},
					{
						displayName: 'Device',
						name: 'device',
						type: 'string',
						default: '',
						placeholder: 'e.g. iphone,desktop',
						description:
							"Name of the device to deliver to, or several names separated by commas. Leave empty to send to all of the user's devices.",
					},
					{
						displayName: 'HTML Formatting',
						name: 'html',
						type: 'boolean',
						default: false,
						description: 'Whether to format the message with HTML tags',
					},
					{
						displayName: 'Sound Name or ID',
						name: 'sound',
						type: 'options',
						typeOptions: { loadOptionsMethod: 'getSounds' },
						default: '',
						description:
							'Choose from the list, or specify an ID using an <a href="https://docs.n8n.io/code/expressions/">expression</a>',
					},
					{
						displayName: 'Timestamp',
						name: 'timestamp',
						type: 'dateTime',
						default: '',
						description:
							'Date and time to show for the message instead of the time Pushover received it. Expressions may also return a Unix timestamp in seconds.',
					},
					{
						displayName: 'Title',
						name: 'title',
						type: 'string',
						default: '',
						description:
							'Title shown above the message, up to 250 characters. When empty, Pushover shows the application name; an encrypted message gets an encrypted "n8n" title instead.',
					},
					{
						displayName: 'TTL (Seconds)',
						name: 'ttl',
						type: 'number',
						typeOptions: { minValue: 0 },
						default: 0,
						description:
							'Seconds after which the message is deleted from the devices. 0 keeps it until the user deletes it.',
					},
					{
						displayName: 'URL',
						name: 'url',
						type: 'string',
						default: '',
						placeholder: 'e.g. https://example.com',
						description: 'A link to show with the message, up to 512 characters',
					},
					{
						displayName: 'URL Title',
						name: 'url_title',
						type: 'string',
						default: '',
						description: 'Text to show for the link instead of the URL, up to 100 characters',
					},
				],
				displayOptions: {
					show: {
						operation: ['sendMessage'],
					},
				},
			},
		],
	};

	methods = {
		loadOptions: {
			async getSounds(this: ILoadOptionsFunctions): Promise<INodePropertyOptions[]> {
				const sounds = await listSounds(this);
				return Object.entries(sounds).map(([value, name]) => ({ name, value }));
			},
		},
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const out: INodeExecutionData[] = [];
		// Set once Pushover refuses the account itself (invalid token, quota
		// used up). Every later request would be refused too, so the remaining
		// items are reported without contacting Pushover again.
		let accountRefusal: { item: number; error: NodeApiError } | undefined;

		const pushError = (i: number, error: string, description?: string | null) => {
			const json: IDataObject = description ? { error, description } : { error };
			out.push(
				...this.helpers.constructExecutionMetaData(this.helpers.returnJsonArray(json), {
					itemData: { item: i },
				}),
			);
		};

		for (let i = 0; i < items.length; i++) {
			if (accountRefusal) {
				const { item, error } = accountRefusal;
				pushError(
					i,
					`Not sent: Pushover refused item ${item} for the whole account (${error.message})`,
					`${error.description ? `${error.description.replace(/\.$/, '')}. ` : ''}Pushover refuses every message from this account until this is fixed, so the node stopped sending; repeated refused requests can get the n8n server's IP address blocked temporarily.`,
				);
				continue;
			}
			try {
				const { fields, attachment } = await buildMessage(this, i);
				const response = await sendMessage(this, fields, attachment);
				out.push(
					...this.helpers.constructExecutionMetaData(this.helpers.returnJsonArray(response), {
						itemData: { item: i },
					}),
				);
			} catch (error) {
				const nodeError = toNodeError(this.getNode(), error, i);
				if (!this.continueOnFail()) throw nodeError;
				if (nodeError instanceof NodeApiError && isAccountLevelError(nodeError)) {
					accountRefusal = { item: i, error: nodeError };
				}
				pushError(i, nodeError.message, nodeError.description);
			}
		}

		return [out];
	}
}

// Surface every failure as an n8n error tied to the failing item. API errors
// from n8n's HTTP helper are already NodeApiError (status code, Pushover's
// error payload) and are kept as they are; NodeOperationError returns an
// existing NodeOperationError unchanged; anything else gets wrapped.
function toNodeError(node: INode, error: unknown, itemIndex: number) {
	if (error instanceof NodeApiError) {
		error.context.itemIndex = itemIndex;
		return error;
	}
	return new NodeOperationError(node, error as Error, { itemIndex });
}

// 'Encrypt Fields' can be set from an expression, or by an AI agent when the
// node runs as a tool, so its value is untrusted. Anything that is not one of
// the four field names fails the item: dropping it silently would send a
// field the user asked to encrypt in plaintext.
function parseEncryptFields(raw: unknown, node: INode, itemIndex: number): EncryptableField[] {
	const list: unknown[] = Array.isArray(raw)
		? raw
		: typeof raw === 'string'
			? raw.split(',')
			: raw === undefined || raw === null
				? []
				: [raw];
	const values = list
		.map((value) => (typeof value === 'string' ? value.trim() : value))
		.filter((value) => value !== '');
	const unsupported = values.filter((value) => !isEncryptableField(value));
	if (unsupported.length > 0) {
		throw new NodeOperationError(
			node,
			`'Encrypt Fields' contains unsupported values: ${unsupported.map((v) => JSON.stringify(v)).join(', ')}`,
			{
				itemIndex,
				description: `Use only ${ENCRYPTABLE_FIELDS.map((f) => `'${f}'`).join(', ')}. Nothing was sent.`,
			},
		);
	}
	return [...new Set(values as EncryptableField[])];
}

// Pushover's `timestamp` is a Unix epoch in *seconds*, but n8n's dateTime
// parameter resolves to an ISO-8601 string (and expressions can yield a
// Luxon DateTime). A bare number or all-digit string is already a Unix value;
// anything else is parsed as a date. Empty → no timestamp.
function toUnixSeconds(raw: unknown, node: INode, itemIndex: number): number | undefined {
	if (raw === '' || raw === undefined || raw === null) return undefined;
	if (typeof raw === 'number') return Math.floor(raw);
	if (/^\d+$/.test(String(raw))) return Number(raw);
	const ms = Date.parse(String(raw));
	if (Number.isNaN(ms)) {
		throw new NodeOperationError(node, `'Timestamp' is not a valid date: "${String(raw)}"`, {
			itemIndex,
			description: 'Use a date and time, an ISO 8601 string, or a Unix timestamp in seconds.',
		});
	}
	return Math.floor(ms / 1000);
}

async function buildMessage(ctx: IExecuteFunctions, i: number): Promise<PushoverMessage> {
	const node = ctx.getNode();
	// Read first: an unusable value must stop the item before anything else.
	const encryptFields = parseEncryptFields(ctx.getNodeParameter('encryptFields', i, []), node, i);
	const userKey = String(ctx.getNodeParameter('userKey', i) ?? '').trim();
	const message = ctx.getNodeParameter('message', i);
	const priority = Number(ctx.getNodeParameter('priority', i));
	const optionalFields = ctx.getNodeParameter('optionalFields', i, {}) as IDataObject;

	// Pushover rejects these anyway, but every rejected request counts towards
	// its temporary IP block, so catch them before sending.
	if (message === undefined || message === null || String(message) === '') {
		throw new NodeOperationError(node, "'Message' is empty", {
			itemIndex: i,
			description: 'Pushover requires a message. Check the expression that sets it.',
		});
	}
	if (!Number.isInteger(priority) || priority < -2 || priority > 2) {
		throw new NodeOperationError(node, `'Priority' must be -2, -1, 0, 1 or 2`, {
			itemIndex: i,
			description: `Received ${JSON.stringify(ctx.getNodeParameter('priority', i))}.`,
		});
	}

	// Values that are not strings (a number from an expression, say) are
	// stringified now, so that they are encrypted like any other text.
	const body: IDataObject = { user: userKey, message: String(message), priority };

	if (priority === 2) {
		body.retry = Number(ctx.getNodeParameter('retry', i));
		body.expire = Number(ctx.getNodeParameter('expire', i));
	}

	for (const name of OPTIONAL_TEXT_FIELDS) {
		const value = optionalFields[name];
		if (value !== undefined && value !== null && String(value) !== '') {
			body[name] = String(value);
		}
	}

	// Pushover expects `html=1`; leave the field out entirely when off.
	if (optionalFields.html === true) {
		body.html = '1';
	}

	const timestamp = toUnixSeconds(optionalFields.timestamp, node, i);
	if (timestamp !== undefined) {
		body.timestamp = timestamp;
	}

	// 0 (the default) means "keep the message", so send no TTL at all. An
	// unusable value fails the item rather than silently keeping a message
	// that was meant to disappear.
	const rawTtl = optionalFields.ttl;
	if (rawTtl !== undefined && rawTtl !== null && rawTtl !== '') {
		const ttl = Number(rawTtl);
		if (!Number.isFinite(ttl) || ttl < 0) {
			throw new NodeOperationError(node, `'TTL (Seconds)' is not a valid duration`, {
				itemIndex: i,
				description: `Use a positive number of seconds, or 0 to keep the message. Received ${JSON.stringify(rawTtl)}.`,
			});
		}
		if (ttl > 0) {
			body.ttl = Math.floor(ttl);
		}
	}

	// The attachment lives in a fixedCollection wrapper; unwrap it into the
	// binary file part Pushover expects as `attachment`.
	let attachment: PushoverAttachment | undefined;
	const wrap = (optionalFields.attachmentsUi as IDataObject | undefined)?.attachment as
		IDataObject | undefined;
	if (wrap?.binaryPropertyName) {
		const propName = String(wrap.binaryPropertyName);
		const binaryMeta = ctx.helpers.assertBinaryData(i, propName);
		attachment = {
			data: await ctx.helpers.getBinaryDataBuffer(i, propName),
			fileName: binaryMeta.fileName,
			mimeType: binaryMeta.mimeType,
		};
	}

	// Encryption runs last, on the final plaintext of every field. The
	// credential is only read when there is something to encrypt.
	if (encryptFields.length > 0) {
		await encryptMessage(ctx, i, body, encryptFields);
	}

	return { fields: body, attachment };
}

async function encryptMessage(
	ctx: IExecuteFunctions,
	i: number,
	body: IDataObject,
	encryptFields: EncryptableField[],
): Promise<void> {
	const node = ctx.getNode();
	const credentials = await ctx.getCredentials<PushoverCredentials>(CREDENTIAL_NAME, i);
	const keyHex = String(credentials.encryptionKey ?? '').trim();
	if (!keyHex) {
		throw new NodeOperationError(node, 'The credential has no encryption key', {
			itemIndex: i,
			description:
				"'Encrypt Fields' selects fields to encrypt, but 'Encryption Key (Hex)' is empty in the credential. Add the 64-character key, or deselect all fields under 'Encrypt Fields' to send the message unencrypted. Nothing was sent.",
		});
	}
	if (!isValidKeyHex(keyHex)) {
		throw new NodeOperationError(node, "The credential's encryption key is not valid", {
			itemIndex: i,
			description:
				"'Encryption Key (Hex)' must be exactly 64 hexadecimal characters (256 bits), for example the output of: openssl rand -hex 32. Nothing was sent.",
		});
	}

	if (encryptFields.includes('title') && body.title === undefined) {
		body.title = ENCRYPTED_TITLE_FALLBACK;
	}

	// Empty and missing fields are not in the body, so there is nothing to
	// encrypt for them (an encrypted message must not carry empty plaintext).
	const present = encryptFields.filter((field) => typeof body[field] === 'string');
	try {
		const ciphertexts = await Promise.all(
			present.map(async (field) => await encryptField(body[field] as string, keyHex)),
		);
		present.forEach((field, k) => (body[field] = ciphertexts[k]));
	} catch (error) {
		throw new NodeOperationError(node, 'The message could not be encrypted', {
			itemIndex: i,
			description: `${(error as Error).message}. Nothing was sent.`,
		});
	}
	// Only flag the message once ciphertext was actually produced, so that
	// Pushover's apps never try to decrypt plaintext.
	if (present.length > 0) {
		body.encrypted = '1';
	}
}
