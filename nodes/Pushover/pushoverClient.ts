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
		throw new NodeApiError(ctx.getNode(), err as JsonObject);
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
