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

import { encryptField, PushoverEncryptionError } from './encryption';
import type { PushoverAttachment } from './pushoverClient';
import { CREDENTIAL_NAME, listSounds, sendMessage } from './pushoverClient';

// Fields whose plaintext can be replaced with a Pushover-encrypted ciphertext
// before the request leaves this node. Attachments are explicitly not in this
// set: Pushover's encryption spec covers text form fields only.
const ENCRYPTABLE_FIELDS = ['message', 'title', 'url', 'url_title'] as const;
type EncryptableField = (typeof ENCRYPTABLE_FIELDS)[number];

// `encryptFields` can be set from an expression, so treat it as untrusted:
// only the four text fields above may ever be replaced with ciphertext.
const isEncryptableField = (value: unknown): value is EncryptableField =>
	(ENCRYPTABLE_FIELDS as readonly unknown[]).includes(value);

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
		subtitle: '={{$parameter["operation"]}}',
		description:
			'Send Pushover notifications with optional client-side AES-256-CBC + HMAC-SHA256 field encryption',
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
				description: 'Recipient key from the Pushover dashboard (often referred to as USER_KEY)',
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
				description: 'Notification body. Pushover limits the plaintext to 1024 UTF-8 characters.',
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
				description: 'For Emergency priority: how often Pushover re-sends until acknowledged',
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
					'For Emergency priority: how long retries continue before giving up (max 10800)',
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
					'Per-field encryption toggles. All four default to ON. Deselect any field you want delivered as plaintext (e.g. keep Title plaintext for a lockscreen preview). Requires the Encryption Key to be set in the credential.',
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
						description:
							"Limit delivery to specific device name(s). Comma-separated for multiple. Omit to send to all of the user's devices.",
					},
					{
						displayName: 'HTML Formatting',
						name: 'html',
						type: 'boolean',
						default: false,
						description: 'Whether the message body uses HTML formatting',
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
							'Unix timestamp Pushover should display for the message, instead of receipt time',
					},
					{
						displayName: 'Title',
						name: 'title',
						type: 'string',
						default: '',
						description: 'Optional title. Falls back to the application name if omitted.',
					},
					{
						displayName: 'TTL (Seconds)',
						name: 'ttl',
						type: 'number',
						default: 0,
						description:
							'After this many seconds the message is auto-deleted from devices. 0 = never.',
					},
					{
						displayName: 'URL',
						name: 'url',
						type: 'string',
						default: '',
						description: 'Supplementary URL shown alongside the message',
					},
					{
						displayName: 'URL Title',
						name: 'url_title',
						type: 'string',
						default: '',
						description: 'Display text for the supplementary URL',
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

		for (let i = 0; i < items.length; i++) {
			try {
				const credentials = await this.getCredentials<PushoverCredentials>(CREDENTIAL_NAME, i);
				const { fields, attachment } = await buildMessage(this, i, credentials);
				const response = await sendMessage(this, fields, credentials.apiKey, attachment);
				const meta = this.helpers.constructExecutionMetaData(
					this.helpers.returnJsonArray(response),
					{
						itemData: { item: i },
					},
				);
				out.push(...meta);
			} catch (error) {
				if (this.continueOnFail()) {
					const meta = this.helpers.constructExecutionMetaData(
						this.helpers.returnJsonArray({ error: (error as Error).message }),
						{ itemData: { item: i } },
					);
					out.push(...meta);
					continue;
				}
				throw toNodeError(this.getNode(), error, i);
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

async function buildMessage(
	ctx: IExecuteFunctions,
	i: number,
	credentials: PushoverCredentials,
): Promise<PushoverMessage> {
	const userKey = ctx.getNodeParameter('userKey', i) as string;
	const message = ctx.getNodeParameter('message', i) as string;
	const priority = ctx.getNodeParameter('priority', i) as number;
	const encryptFields = (ctx.getNodeParameter('encryptFields', i, []) as unknown[]).filter(
		isEncryptableField,
	);
	const optionalFields = ctx.getNodeParameter('optionalFields', i, {}) as IDataObject;

	const body: IDataObject = {
		user: userKey,
		message,
		priority,
	};

	if (priority === 2) {
		body.retry = ctx.getNodeParameter('retry', i) as number;
		body.expire = ctx.getNodeParameter('expire', i) as number;
	}

	// Promote optional fields up to top-level keys, applying the HTML
	// boolean → '1' conversion Pushover expects. We omit the field entirely
	// when false so we don't ship an empty `html=""` form value.
	if (optionalFields.html === true) {
		optionalFields.html = '1';
	} else {
		delete optionalFields.html;
	}

	// Pushover's `timestamp` is a Unix epoch in *seconds*, but n8n's dateTime
	// parameter resolves to an ISO-8601 string (and expressions can yield a
	// Luxon DateTime). Sending that string makes Pushover reject or ignore the
	// value, so coerce it here. A bare number or all-digit string is already a
	// Unix value; anything else is parsed as a date. Empty → drop the field.
	if ('timestamp' in optionalFields) {
		const raw = optionalFields.timestamp;
		if (raw === '' || raw == null) {
			delete optionalFields.timestamp;
		} else if (typeof raw === 'number') {
			optionalFields.timestamp = Math.floor(raw);
		} else if (/^\d+$/.test(String(raw))) {
			optionalFields.timestamp = Number(raw);
		} else {
			const ms = Date.parse(String(raw));
			if (Number.isNaN(ms)) {
				throw new NodeOperationError(
					ctx.getNode(),
					`Timestamp "${String(raw)}" is not a valid date or Unix timestamp`,
					{ itemIndex: i },
				);
			}
			optionalFields.timestamp = Math.floor(ms / 1000);
		}
	}

	Object.assign(body, optionalFields);

	// Attachment lives in a fixedCollection wrapper; unwrap it into the binary
	// file part Pushover expects as `attachment`.
	let attachment: PushoverAttachment | undefined;
	if (body.attachmentsUi) {
		const wrap = (body.attachmentsUi as IDataObject).attachment as IDataObject | undefined;
		if (wrap?.binaryPropertyName) {
			const propName = wrap.binaryPropertyName as string;
			const binaryMeta = ctx.helpers.assertBinaryData(i, propName);
			attachment = {
				data: await ctx.helpers.getBinaryDataBuffer(i, propName),
				fileName: binaryMeta.fileName,
				mimeType: binaryMeta.mimeType,
			};
		}
		delete body.attachmentsUi;
	}

	// Encryption is applied last so it sees the final plaintext for every
	// field, including ones merged from optionalFields.
	if (encryptFields.length > 0) {
		const keyHex = credentials.encryptionKey?.trim();
		if (!keyHex) {
			throw new NodeOperationError(
				ctx.getNode(),
				'Encrypt Fields is non-empty but no Encryption Key is set on the credential. Either set a 64-character hex key, or deselect all fields under Encrypt Fields to send plaintext.',
				{ itemIndex: i },
			);
		}
		// Skip fields that aren't present or are empty — sending an empty
		// plaintext value alongside encrypted=1 confuses receiving devices
		// (they try to decrypt the empty string and produce garbage).
		let anyEncrypted = false;
		for (const field of encryptFields) {
			const value = body[field];
			if (typeof value === 'string' && value.length > 0) {
				try {
					body[field] = await encryptField(value, keyHex);
					anyEncrypted = true;
				} catch (error) {
					const msg =
						error instanceof PushoverEncryptionError
							? error.message
							: 'Unexpected error during field encryption';
					throw new NodeOperationError(ctx.getNode(), msg, { itemIndex: i });
				}
			} else if (typeof value === 'string' && value.length === 0) {
				delete body[field];
			}
		}
		// Only flip the encrypted flag if we actually produced ciphertext —
		// otherwise we'd tell Pushover to treat plaintext fields as encrypted.
		if (anyEncrypted) {
			body.encrypted = '1';
		}
	}

	return { fields: body, attachment };
}
