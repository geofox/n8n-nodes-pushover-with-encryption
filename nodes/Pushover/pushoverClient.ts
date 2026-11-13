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
//
// The application token is appended here on purpose: n8n applies a
// `generic` credential by assigning `body[key] = value`, which turns into a
// form field for a plain-object body but only sets an inert JS property on a
// FormData instance. The credential still adds `token` to the query string,
// so the request carries it in both places, exactly as the previous
// request-library based implementation did.
export function toMultipartBody(
	fields: IDataObject,
	token: string,
	attachment?: PushoverAttachment,
): FormData {
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
	form.append('token', token);
	return form;
}

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
	throw new NodeApiError(ctx.getNode(), (isJsonObject ? payload : {}) as JsonObject, {
		httpCode: String(response.statusCode),
	});
}

export async function sendMessage(
	ctx: IExecuteFunctions,
	fields: IDataObject,
	token: string,
	attachment?: PushoverAttachment,
): Promise<IDataObject> {
	return await request(ctx, 'POST', '/messages.json', toMultipartBody(fields, token, attachment));
}

export async function listSounds(ctx: ILoadOptionsFunctions): Promise<Record<string, string>> {
	const response = await request(ctx, 'GET', '/sounds.json');
	const sounds = response.sounds as Record<string, string> | undefined;
	return sounds ?? {};
}
