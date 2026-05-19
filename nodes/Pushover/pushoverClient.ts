import type {
	IDataObject,
	IExecuteFunctions,
	IHttpRequestMethods,
	IHttpRequestOptions,
	ILoadOptionsFunctions,
	JsonObject,
} from 'n8n-workflow';
import { NodeApiError } from 'n8n-workflow';

const BASE_URL = 'https://api.pushover.net/1';
const CRED_NAME = 'pushoverWithEncryptionApi';

type PushoverContext = IExecuteFunctions | ILoadOptionsFunctions;

async function request(
	ctx: PushoverContext,
	method: IHttpRequestMethods,
	endpoint: string,
	body?: IDataObject,
): Promise<IDataObject> {
	// json:true tells n8n's HTTP helper to parse the response as JSON (so we
	// can pull `response.sounds` etc downstream). The explicit multipart
	// Content-Type is what Pushover's /messages.json expects, and n8n's
	// helper preserves it when serializing the body — this matches the
	// pattern n8n's own built-in Pushover node uses and is confirmed by
	// live successful sends. Don't drop either without testing both the
	// plain-message and attachment paths against the live API.
	const options: IHttpRequestOptions = {
		method,
		url: `${BASE_URL}${endpoint}`,
		json: true,
		headers: {
			'Content-Type': 'multipart/form-data',
		},
	};

	if (body && Object.keys(body).length > 0) {
		options.body = body;
	}

	try {
		return (await ctx.helpers.requestWithAuthentication.call(
			ctx,
			CRED_NAME,
			options,
		)) as IDataObject;
	} catch (err) {
		// Pre-existing NodeApiError → pass through. Otherwise build one
		// defensively: HTTP-layer errors are typically IDataObject-shaped
		// (statusCode, body, etc), but network errors (DNS, timeout) arrive
		// as plain Error instances without those fields. Casting Error to
		// JsonObject silently produces a NodeApiError with an empty message,
		// which surfaces in the UI as "undefined".
		if (err instanceof NodeApiError) throw err;
		const node = ctx.getNode();
		if (err && typeof err === 'object') {
			throw new NodeApiError(node, err as JsonObject);
		}
		throw new NodeApiError(node, {
			message: err instanceof Error ? err.message : String(err),
		});
	}
}

export async function sendMessage(
	ctx: IExecuteFunctions,
	body: IDataObject,
): Promise<IDataObject> {
	return request(ctx, 'POST', '/messages.json', body);
}

export async function listSounds(ctx: ILoadOptionsFunctions): Promise<Record<string, string>> {
	const response = await request(ctx, 'GET', '/sounds.json');
	const sounds = response.sounds as Record<string, string> | undefined;
	return sounds ?? {};
}
