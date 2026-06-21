import type { Env, SessionRow } from './types';
import { RATE_LIMIT_PER_MIN, RATE_LIMIT_WINDOW_MS, POST_SLUG_MAX_LENGTH } from './types';

export function json(payload: unknown, status = 200, extraHeaders: Record<string, string> = {}): Response {
	return new Response(JSON.stringify(payload), {
		status,
		headers: {
			'content-type': 'application/json; charset=utf-8',
			'cache-control': 'no-store',
			...extraHeaders,
		},
	});
}

export function cookie(name: string, value: string, maxAge: number): string {
	return [
		`${name}=${encodeURIComponent(value)}`,
		'Path=/',
		`Max-Age=${Math.max(0, Math.floor(maxAge))}`,
		'HttpOnly',
		'Secure',
		'SameSite=Lax',
	].join('; ');
}

export function clearCookie(name: string): string {
	return cookie(name, '', 0);
}

export function parseCookies(raw: string | null): Map<string, string> {
	const out = new Map<string, string>();
	if (!raw) return out;
	for (const part of raw.split(';')) {
		const i = part.indexOf('=');
		if (i <= 0) continue;
		const k = part.slice(0, i).trim();
		const v = part.slice(i + 1).trim();
		try {
			out.set(k, decodeURIComponent(v));
		} catch {
			out.set(k, v);
		}
	}
	return out;
}

export function bearerToken(request: Request): string | null {
	const auth = request.headers.get('authorization') ?? '';
	const match = auth.match(/^Bearer\s+([A-Za-z0-9._~-]{20,512})$/i);
	return match ? match[1] : null;
}

export function clientIp(request: Request): string {
	const raw = request.headers.get('CF-Connecting-IP') ?? request.headers.get('x-forwarded-for') ?? 'unknown';
	return raw.split(',')[0]?.trim().slice(0, 80) || 'unknown';
}

export function getClientIp(request: Request): string {
	const forwarded = request.headers.get('CF-Connecting-IP');
	if (forwarded) return forwarded.split(',')[0].trim();
	const realIp = request.headers.get('X-Real-IP');
	if (realIp) return realIp;
	return 'unknown';
}

export function escapeHtml(value: string): string {
	return value
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#39;');
}

export function randomBase64Url(byteLength: number): string {
	const bytes = new Uint8Array(byteLength);
	crypto.getRandomValues(bytes);
	return toBase64Url(bytes);
}

export async function sha256Base64Url(value: string): Promise<string> {
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
	return toBase64Url(new Uint8Array(digest));
}

export function toBase64Url(bytes: Uint8Array): string {
	let binary = '';
	for (const b of bytes) binary += String.fromCharCode(b);
	return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function safeEqual(a: string, b: string): boolean {
	const len = Math.max(a.length, b.length);
	let mismatch = a.length === b.length ? 0 : 1;
	for (let i = 0; i < len; i += 1) {
		mismatch |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
	}
	return mismatch === 0;
}

export function clampInt(value: unknown, min: number, max: number, fallback: number): number {
	const n = Number(value);
	if (!Number.isFinite(n)) return fallback;
	return Math.max(min, Math.min(max, Math.floor(n)));
}

export function normalizePostSlug(input: unknown): string | null {
	if (typeof input !== 'string') return null;
	const trimmed = input.trim();
	if (!trimmed || trimmed.length > POST_SLUG_MAX_LENGTH) return null;
	if (!/^[A-Za-z0-9/_-]+$/.test(trimmed)) return null;
	return trimmed;
}

export function normalizeAvatarUrl(input: unknown): string | null {
	if (input === null) return null;
	if (typeof input !== 'string') return null;
	const trimmed = input.trim();
	if (!trimmed) return null;
	if (trimmed.length > 1000) return null;
	try {
		const url = new URL(trimmed);
		if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
		return url.toString();
	} catch {
		return null;
	}
}

export function containsHtml(text: string): boolean {
	return /<[^>]*>/.test(text) || text.includes('<') || text.includes('>');
}

export function syntheticGithubIdForKey(key: string): number {
	let hash = 2166136261;
	for (let i = 0; i < key.length; i += 1) {
		hash ^= key.charCodeAt(i);
		hash = Math.imul(hash, 16777619);
	}
	return -Math.max(1, hash >>> 0);
}

export async function findSessionUser(env: Env, token: string): Promise<SessionRow | null> {
	const row = await env.DB.prepare(
		`SELECT
		 s.user_id AS user_id,
		 s.expires_at AS expires_at,
		 u.login AS login,
		 u.name AS name,
		 u.avatar_url AS avatar_url,
		 u.profile_url AS profile_url
		 FROM sessions s
		 JOIN users u ON u.id = s.user_id
		 WHERE s.id = ?
		 LIMIT 1`
	)
		.bind(token)
		.first<SessionRow>();

	if (!row) return null;

	if (Number(row.expires_at) <= Date.now()) {
		await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(token).run();
		return null;
	}

	return row;
}

export async function checkRateLimit(request: Request, env: Env, route: string): Promise<Response | null> {
	const ip = clientIp(request);

	if (!env.RATE_LIMITER) {
		// Fallback to KV rate limiting for Cloudflare Free Plan
		const now = Date.now();
		const bucket = Math.floor(now / RATE_LIMIT_WINDOW_MS);
		const key = `rl:${ip}:${route}:${bucket}`;
		
		let count = 0;
		if (env.RATE_LIMIT_KV) {
			const stored = await env.RATE_LIMIT_KV.get(key);
			count = stored ? parseInt(stored, 10) : 0;
			if (count >= RATE_LIMIT_PER_MIN) {
				const retryAfter = Math.max(1, Math.ceil(((bucket + 1) * RATE_LIMIT_WINDOW_MS - now) / 1000));
				return json({ error: 'Too Many Requests' }, 429, {
					'retry-after': String(retryAfter),
				});
			}
			await env.RATE_LIMIT_KV.put(key, String(count + 1), { expirationTtl: 120 });
		}
		return null;
	}

	const id = env.RATE_LIMITER.idFromName(ip);
	const stub = env.RATE_LIMITER.get(id);

	const res = await stub.fetch('https://rate-limiter.internal/consume', {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({
			ip,
			route,
			limit: RATE_LIMIT_PER_MIN,
			windowMs: RATE_LIMIT_WINDOW_MS,
		}),
	});

	if (res.status !== 429) return null;

	return json({ error: 'Too Many Requests' }, 429, {
		'retry-after': res.headers.get('retry-after') ?? '60',
	});
}

export function resolveAllowedOrigin(request: Request, env: Env): string | null {
	const origin = request.headers.get('origin');
	if (!origin) return null;
	return isAllowedExternalOrigin(origin, env.PUBLIC_ALLOWED_ORIGIN) ? origin : null;
}

export function isAllowedExternalOrigin(origin: string, envAllowList?: string): boolean {
	if (/^https:\/\/[a-z0-9-]+\.pages\.dev$/i.test(origin)) return true;
	const list = (envAllowList ?? '')
		.split(',')
		.map((s) => s.trim())
		.filter(Boolean);
	return list.includes(origin);
}

export function firstAllowedOriginFromEnv(envAllowList?: string): string | null {
	const list = (envAllowList ?? '')
		.split(',')
		.map((s) => s.trim())
		.filter(Boolean);
	return list[0] ?? null;
}

export function withCors(response: Response, origin: string | null): Response {
	if (!origin) return response;
	const headers = new Headers(response.headers);
	headers.set('access-control-allow-origin', origin);
	headers.set('vary', 'Origin');
	headers.set('access-control-allow-headers', 'Authorization, Content-Type');
	headers.set('access-control-allow-methods', 'GET,POST,OPTIONS');
	return new Response(response.body, {
		status: response.status,
		statusText: response.statusText,
		headers,
	});
}

export function sanitizeReturnTo(raw: string | null, env: Env): string {
	const fallbackOrigin = firstAllowedOriginFromEnv(env.PUBLIC_ALLOWED_ORIGIN);
	const fallback = fallbackOrigin || '/';
	if (!raw) return fallback;

	if (raw.startsWith('/')) {
		return fallbackOrigin ? new URL(raw, fallbackOrigin).toString() : raw;
	}

	try {
		const url = new URL(raw);
		if (isAllowedExternalOrigin(url.origin, env.PUBLIC_ALLOWED_ORIGIN)) {
			return url.toString();
		}
	} catch {
		return fallback;
	}

	return fallback;
}
