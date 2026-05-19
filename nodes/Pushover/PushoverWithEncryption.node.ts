import type {
	IDataObject,
	IExecuteFunctions,
	ILoadOptionsFunctions,
	INodeExecutionData,
	INodePropertyOptions,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';
import { NodeOperationError } from 'n8n-workflow';

import { encryptField, PushoverEncryptionError } from './encryption';
import { listSounds, sendMessage } from './pushoverClient';

// Fields whose plaintext can be replaced with a Pushover-encrypted ciphertext
// before the request leaves this node. Attachments are explicitly not in this
// set: Pushover's encryption spec covers text form fields only.
const ENCRYPTABLE_FIELDS = ['message', 'title', 'url', 'url_title'] as const;
type EncryptableField = (typeof ENCRYPTABLE_FIELDS)[number];

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
		icon: 'file:pushover.svg',
		group: ['output'],
		version: 1,
		subtitle: '={{$parameter["operation"]}}',
		description:
			'Send Pushover notifications with optional client-side AES-256-CBC + HMAC-SHA256 field encryption',
		defaults: {
			name: 'Pushover (with Encryption)',
		},
		usableAsTool: true,
		inputs: ['main'],
		outputs: ['main'],
		credentials: [
			{
				name: 'pushoverWithEncryptionApi',
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
				// eslint-disable-next-line n8n-nodes-base/node-param-options-type-unsorted-items
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
				description: 'For Emergency priority: how long retries continue before giving up (max 10800)',
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
						description: 'After this many seconds the message is auto-deleted from devices. 0 = never.',
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
				const body = await buildRequestBody(this, i);
				const response = await sendMessage(this, body);
				const meta = this.helpers.constructExecutionMetaData(this.helpers.returnJsonArray(response), {
					itemData: { item: i },
				});
				out.push(...meta);
			} catch (err) {
				if (this.continueOnFail()) {
					const meta = this.helpers.constructExecutionMetaData(
						this.helpers.returnJsonArray({ error: (err as Error).message }),
						{ itemData: { item: i } },
					);
					out.push(...meta);
					continue;
				}
				throw err;
			}
		}

		return [out];
	}
}

async function buildRequestBody(ctx: IExecuteFunctions, i: number): Promise<IDataObject> {
	const userKey = ctx.getNodeParameter('userKey', i) as string;
	const message = ctx.getNodeParameter('message', i) as string;
	const priority = ctx.getNodeParameter('priority', i) as number;
	const encryptFields = ctx.getNodeParameter('encryptFields', i, []) as EncryptableField[];
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
	Object.assign(body, optionalFields);

	// Attachment lives in a fixedCollection wrapper; unwrap it into the
	// `attachment` field Pushover expects (a Buffer with filename metadata).
	if (body.attachmentsUi) {
		const wrap = (body.attachmentsUi as IDataObject).attachment as IDataObject | undefined;
		if (wrap?.binaryPropertyName) {
			const propName = wrap.binaryPropertyName as string;
			const binaryMeta = ctx.helpers.assertBinaryData(i, propName);
			const buffer = await ctx.helpers.getBinaryDataBuffer(i, propName);
			body.attachment = {
				value: buffer,
				options: { filename: binaryMeta.fileName },
			};
		}
		delete body.attachmentsUi;
	}

	// Encryption is applied last so it sees the final plaintext for every
	// field, including ones merged from optionalFields.
	if (encryptFields.length > 0) {
		const credentials = await ctx.getCredentials('pushoverWithEncryptionApi');
		const keyHex = (credentials.encryptionKey as string | undefined)?.trim();
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
					body[field] = encryptField(value, keyHex);
					anyEncrypted = true;
				} catch (err) {
					const msg =
						err instanceof PushoverEncryptionError
							? err.message
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

	return body;
}
