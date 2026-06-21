import type { Env } from './types';
import { json, bearerToken, findSessionUser, checkRateLimit } from './utils';

export async function handleImageRoute(request: Request, env: Env): Promise<Response> {
	const url = new URL(request.url);
	if (url.searchParams.has('prefix')) return handleImageList(request, env);
	if (url.searchParams.has('key')) return handleImageServe(request, env);
	return handleImageList(request, env);
}

async function handleImageServe(request: Request, env: Env): Promise<Response> {
	const url = new URL(request.url);
	const key = url.searchParams.get('key');
	if (!key) return json({ error: 'Missing key parameter' }, 400);

	const safeKey = key.replace(/[^a-zA-Z0-9\-_./]/g, '');

	try {
		const object = await env.IMAGES.get(safeKey);
		if (!object) return json({ error: 'Image not found' }, 404);

		const headers = new Headers();
		headers.set('Content-Type', object.httpEtag.includes('image') ? 'image/webp' : 'application/octet-stream');
		headers.set('Cache-Control', 'public, max-age=31536000');

		return new Response(object.body, { headers });
	} catch (error) {
		console.error('R2 get error:', error);
		return json({ error: 'Failed to get image' }, 500);
	}
}

async function handleImageList(request: Request, env: Env): Promise<Response> {
	const token = bearerToken(request);
	if (!token) return json({ error: 'Unauthorized' }, 401);

	const session = await findSessionUser(env, token);
	if (!session) return json({ error: 'Unauthorized' }, 401);

	const url = new URL(request.url);
	const prefix = url.searchParams.get('prefix') || '';
	const cursor = url.searchParams.get('cursor') || undefined;
	const limit = Math.min(parseInt(url.searchParams.get('limit') || '100'), 1000);

	const safePrefix = prefix.replace(/[^a-zA-Z0-9\-_/]/g, '');
	const userPrefix = `images/${session.user_id}/`;
	const effectivePrefix = safePrefix ? `${userPrefix}${safePrefix}/` : userPrefix;

	try {
		const result = await env.IMAGES.list({ prefix: effectivePrefix, limit, cursor, delimiter: '/' });

		const images = result.objects.map((obj) => ({
			key: obj.key,
			size: obj.size,
			url: `${env.R2_PUBLIC_URL || 'https://img.danarnoux.com'}/${obj.key}`,
		}));

		return json({ images, truncated: result.truncated, cursor: result.truncated ? result.cursor : undefined });
	} catch (error) {
		console.error('R2 list error:', error);
		return json({ error: 'Failed to list images' }, 500);
	}
}

export async function handleImageUpload(request: Request, env: Env): Promise<Response> {
	const token = bearerToken(request);
	if (!token) return json({ error: 'Unauthorized' }, 401);

	const session = await findSessionUser(env, token);
	if (!session) return json({ error: 'Unauthorized' }, 401);

	const rateLimitRes = await checkRateLimit(request, env, 'image_upload');
	if (rateLimitRes) return rateLimitRes;

	const contentType = request.headers.get('content-type') || '';
	if (!contentType.startsWith('image/')) {
		return json({ error: 'Content-Type must be an image' }, 400);
	}

	const url = new URL(request.url);
	const filename = url.searchParams.get('filename') || 'image';
	const category = url.searchParams.get('category') || 'misc';

	const validCategories = ['posts', 'avatars', 'misc'];
	const safeCategory = validCategories.includes(category) ? category : 'misc';
	const safeFilename = filename.replace(/[^a-zA-Z0-9\-_.]/g, '_').replace(/^\.+/, '') || 'image';
	const safeUserId = session.user_id.replace(':', '_');
	const key = safeCategory === 'avatars'
		? `avatars/${safeUserId}/${safeFilename}`
		: `${safeCategory}/${safeFilename}`;

	try {
		const arrayBuffer = await request.arrayBuffer();
		await env.IMAGES.put(key, arrayBuffer);

		const imageUrl = `${env.R2_PUBLIC_URL || 'https://img.danarnoux.com'}/${key}`;
		return json({ key, url: imageUrl }, 201);
	} catch (error) {
		console.error('R2 upload error:', error);
		return json({ error: 'Failed to upload image' }, 500);
	}
}

export async function handleImageDelete(request: Request, env: Env): Promise<Response> {
	const token = bearerToken(request);
	if (!token) return json({ error: 'Unauthorized' }, 401);

	const session = await findSessionUser(env, token);
	if (!session) return json({ error: 'Unauthorized' }, 401);

	let payload: { key?: unknown };
	try {
		payload = (await request.json()) as { key?: unknown };
	} catch {
		return json({ error: 'Invalid JSON' }, 400);
	}

	const key = typeof payload.key === 'string' ? payload.key : '';
	if (!key) return json({ error: 'Missing key parameter' }, 400);

	if (!key.startsWith(`images/${session.user_id}/`)) {
		return json({ error: 'Cannot delete other users\' images' }, 403);
	}

	try {
		await env.IMAGES.delete(key);
		return json({ ok: true });
	} catch (error) {
		console.error('R2 delete error:', error);
		return json({ error: 'Failed to delete image' }, 500);
	}
}
