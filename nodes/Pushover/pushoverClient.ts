import type {
	IDataObject,
	IExecuteFunctions,
	IHttpRequestMethods,
	IHttpRequestOptions,
	ILoadOptionsFunctions,
	IN8nHttpFullResponse,
	JsonObject,
} from 'n8n-workflow';
import { NodeApiError } from 'n8n-workflow';

const BASE_URL = 'https://api.pushover.net/1';
export const CREDENTIAL_NAME = 'pushoverWithEncryptionApi';

type PushoverContext = IExecuteFunctions | ILoadOptionsFunctions;

export interface PushoverAttachment {
	data: Buffer;
	fileName?: string;
	mimeType?: string;
}

// Pushover's /messages.json takes a multipart/form-data POST. The body is a
// WHATWG FormData (a Node.js global, so no runtime dependency), which n8n's
// HTTP helper hands to axios as-is and axios streams with a proper boundary.
// The application token is not added here: the credential's `authenticate`
// method appends it to the form body when the request is sent.
export function toMultipartBody(fields: IDataObject, attachment?: PushoverAttachment): FormData {
	const form = new FormData();
	for (const [name, value] of Object.entries(fields)) {
		if (value === undefined || value === null) continue;
		form.append(name, typeof value === 'string' ? value : String(value));
	}
	if (attachment) {
		form.append(
			'attachment',
			new Blob([attachment.data], { type: attachment.mimeType || 'application/octet-stream' }),
			attachment.fileName || 'attachment',
		);
	}
	return form;
}

// Errors after which every further request from this account is rejected
// too, so sending the remaining items would only add failed requests. Pushover
// temporarily blocks IPs that send many failing requests within minutes.
const accountLevelErrors = new WeakSet<object>();

export const isAccountLevelError = (error: unknown): boolean =>
	typeof error === 'object' && error !== null && accountLevelErrors.has(error);

async function request(
	ctx: PushoverContext,
	method: IHttpRequestMethods,
	endpoint: string,
	body?: FormData,
): Promise<IDataObject> {
	// json:true asks n8n to send `Accept: application/json` and parse the
	// response. Do not set Content-Type for the FormData body: axios has to
	// generate it so that it includes the multipart boundary.
	//
	// HTTP error statuses are returned rather than thrown so that the error
	// can be built from Pushover's JSON body: Pushover reports problems in an
	// `errors` array, which n8n only picks up as the error description when
	// it is given the body itself (from an axios error it shows the generic
	// "Request failed with status code 400" instead).
	const options: IHttpRequestOptions = {
		method,
		url: `${BASE_URL}${endpoint}`,
		json: true,
		ignoreHttpStatusErrors: true,
		returnFullResponse: true,
	};
	if (body) {
		options.body = body;
	}

	// Transport failures (DNS, TLS, timeouts) still throw, already wrapped
	// by n8n in NodeApiError.
	const response = (await ctx.helpers.httpRequestWithAuthentication.call(
		ctx,
		CREDENTIAL_NAME,
		options,
	)) as IN8nHttpFullResponse;

	const payload = response.body;
	const isJsonObject = typeof payload === 'object' && payload !== null && !Array.isArray(payload);
	if (response.statusCode >= 200 && response.statusCode < 300) {
		return (isJsonObject ? payload : {}) as IDataObject;
	}
	const errorBody = (isJsonObject ? payload : {}) as JsonObject;
	const error = new NodeApiError(ctx.getNode(), errorBody, {
		httpCode: String(response.statusCode),
	});
	// 429: the account is over its monthly message quota, and Pushover rejects
	// every message until the quota resets. 401/403 or `"token": "invalid"`
	// (the same shape as Pushover's documented `"user": "invalid"`): the
	// application token itself was refused.
	if ([401, 403, 429].includes(response.statusCode) || errorBody.token === 'invalid') {
		accountLevelErrors.add(error);
	}
	throw error;
}

export async function sendMessage(
	ctx: IExecuteFunctions,
	fields: IDataObject,
	attachment?: PushoverAttachment,
): Promise<IDataObject> {
	return await request(ctx, 'POST', '/messages.json', toMultipartBody(fields, attachment));
}

export async function listSounds(ctx: ILoadOptionsFunctions): Promise<Record<string, string>> {
	const response = await request(ctx, 'GET', '/sounds.json');
	const sounds = response.sounds as Record<string, string> | undefined;
	return sounds ?? {};
}
