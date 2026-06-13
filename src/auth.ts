import type { Env } from './types';
import {
	STATE_COOKIE, VERIFIER_COOKIE, RETURN_TO_COOKIE,
	OAUTH_COOKIE_TTL_SECONDS, FRONTEND_URL,
} from './types';
import {
	json, cookie, clearCookie, parseCookies, bearerToken, clientIp, getClientIp,
	escapeHtml, randomBase64Url, sha256Base64Url, safeEqual, clampInt,
	normalizeAvatarUrl, syntheticGithubIdForKey, findSessionUser, checkRateLimit,
	sanitizeReturnTo,
} from './utils';
import { moderateUsername } from './moderation';

export async function handleGithubStart(request: Request, env: Env): Promise<Response> {
	if (!env.GITHUB_CLIENT_ID) {
		return json({ error: 'GITHUB_CLIENT_ID is required' }, 500);
	}

	const rate = await checkRateLimit(request, env, 'oauth_start');
	if (rate) return rate;

	const requestUrl = new URL(request.url);
	const state = randomBase64Url(24);
	const codeVerifier = randomBase64Url(48);
	const codeChallenge = await sha256Base64Url(codeVerifier);
	const returnTo = sanitizeReturnTo(requestUrl.searchParams.get('returnTo'), env);
	const redirectUri = `${requestUrl.origin}/api/auth/github/callback`;

	const githubAuth = new URL('https://github.com/login/oauth/authorize');
	githubAuth.searchParams.set('client_id', env.GITHUB_CLIENT_ID);
	githubAuth.searchParams.set('redirect_uri', redirectUri);
	githubAuth.searchParams.set('scope', 'read:user');
	githubAuth.searchParams.set('state', state);
	githubAuth.searchParams.set('code_challenge', codeChallenge);
	githubAuth.searchParams.set('code_challenge_method', 'S256');

	const headers = new Headers({ location: githubAuth.toString(), 'cache-control': 'no-store' });
	headers.append('set-cookie', cookie(STATE_COOKIE, state, OAUTH_COOKIE_TTL_SECONDS));
	headers.append('set-cookie', cookie(VERIFIER_COOKIE, codeVerifier, OAUTH_COOKIE_TTL_SECONDS));
	headers.append('set-cookie', cookie(RETURN_TO_COOKIE, returnTo, OAUTH_COOKIE_TTL_SECONDS));

	return new Response(null, { status: 302, headers });
}

export async function handleGithubCallback(request: Request, env: Env): Promise<Response> {
	if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET) {
		return json({ error: 'OAuth secrets are not configured' }, 500);
	}

	const requestUrl = new URL(request.url);
	const cookies = parseCookies(request.headers.get('cookie'));
	const stateExpected = cookies.get(STATE_COOKIE) ?? '';
	const verifier = cookies.get(VERIFIER_COOKIE) ?? '';
	const returnTo = sanitizeReturnTo(cookies.get(RETURN_TO_COOKIE) ?? '', env);
	const state = requestUrl.searchParams.get('state') ?? '';
	const code = requestUrl.searchParams.get('code') ?? '';

	if (!stateExpected || !verifier || !state || !code || !safeEqual(stateExpected, state)) {
		return redirectWithClearedOAuth(returnTo);
	}

	const tokenPayload = new URLSearchParams();
	tokenPayload.set('client_id', env.GITHUB_CLIENT_ID);
	tokenPayload.set('client_secret', env.GITHUB_CLIENT_SECRET);
	tokenPayload.set('code', code);
	tokenPayload.set('code_verifier', verifier);
	tokenPayload.set('redirect_uri', `${requestUrl.origin}/api/auth/github/callback`);

	const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
		method: 'POST',
		headers: {
			accept: 'application/json',
			'content-type': 'application/x-www-form-urlencoded',
			'user-agent': 'blog-worker',
		},
		body: tokenPayload,
	});

	if (!tokenRes.ok) return redirectWithClearedOAuth(returnTo);

	const tokenData = (await tokenRes.json()) as { access_token?: string };
	const githubAccessToken = typeof tokenData.access_token === 'string' ? tokenData.access_token : '';
	if (!githubAccessToken) return redirectWithClearedOAuth(returnTo);

	const userRes = await fetch('https://api.github.com/user', {
		headers: {
			accept: 'application/vnd.github+json',
			authorization: `Bearer ${githubAccessToken}`,
			'user-agent': 'blog-worker',
		},
	});

	if (!userRes.ok) return redirectWithClearedOAuth(returnTo);

	const ghUser = (await userRes.json()) as {
		id: number;
		login: string;
		name?: string | null;
		avatar_url?: string | null;
		html_url?: string | null;
	};

	if (!ghUser || typeof ghUser.id !== 'number' || typeof ghUser.login !== 'string') {
		return redirectWithClearedOAuth(returnTo);
	}

	const now = Date.now();
	const userId = `github:${ghUser.id}`;

	await env.DB.prepare(
		`INSERT INTO users (id, github_id, login, name, avatar_url, profile_url, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(github_id) DO UPDATE SET
		   login = excluded.login,
		   name = excluded.name,
		   avatar_url = excluded.avatar_url,
		   profile_url = excluded.profile_url,
		   updated_at = excluded.updated_at`
	)
		.bind(userId, ghUser.id, ghUser.login, ghUser.name ?? null, ghUser.avatar_url ?? null, ghUser.html_url ?? null, now, now)
		.run();

	const sessionTtlSeconds = clampInt(env.SESSION_TTL_SECONDS, 300, 365 * 24 * 3600, 30 * 24 * 3600);
	const sessionToken = randomBase64Url(32);
	const expiresAt = now + sessionTtlSeconds * 1000;

	await env.DB.prepare(
		`INSERT INTO sessions (id, user_id, created_at, expires_at, ip, user_agent)
		 VALUES (?, ?, ?, ?, ?, ?)`
	)
		.bind(sessionToken, userId, now, expiresAt, clientIp(request), (request.headers.get('user-agent') ?? '').slice(0, 256))
		.run();

	const redirectTo = `${FRONTEND_URL}/#token=${encodeURIComponent(sessionToken)}`;
	const headers = new Headers({ location: redirectTo, 'cache-control': 'no-store' });
	headers.append('set-cookie', clearCookie(STATE_COOKIE));
	headers.append('set-cookie', clearCookie(VERIFIER_COOKIE));
	headers.append('set-cookie', clearCookie(RETURN_TO_COOKIE));

	return new Response(null, { status: 302, headers });
}

export async function handleMe(request: Request, env: Env): Promise<Response> {
	const token = bearerToken(request);
	if (!token) return json({ error: 'Unauthorized' }, 401);

	const row = await findSessionUser(env, token);
	if (!row) return json({ error: 'Unauthorized' }, 401);

	return json({
		user: {
			id: row.user_id,
			login: row.login,
			name: row.name,
			avatarUrl: row.avatar_url,
			profileUrl: row.profile_url,
		},
	});
}

export async function handleMeUpdate(request: Request, env: Env): Promise<Response> {
	const token = bearerToken(request);
	if (!token) return json({ error: 'Unauthorized' }, 401);

	const session = await findSessionUser(env, token);
	if (!session) return json({ error: 'Unauthorized' }, 401);

	if (!request.headers.get('content-type')?.includes('application/json')) {
		return json({ error: 'Content-Type must be application/json' }, 415);
	}

	let payload: { avatarUrl?: unknown; username?: unknown };
	try {
		payload = (await request.json()) as { avatarUrl?: unknown; username?: unknown };
	} catch {
		return json({ error: 'Invalid JSON' }, 400);
	}

	const avatarUrl = normalizeAvatarUrl(payload.avatarUrl);
	if (payload.avatarUrl !== undefined && avatarUrl === null) {
		return json({ error: 'Invalid avatar URL' }, 400);
	}

	let newName = session.name;
	let shouldUpdateName = false;
	if (payload.username !== undefined) {
		const usernameStr = typeof payload.username === 'string' ? payload.username.trim() : '';
		if (!usernameStr) return json({ error: 'Username cannot be empty' }, 400);
		if (usernameStr.length < 2 || usernameStr.length > 30) {
			return json({ error: 'Username must be 2-30 characters' }, 400);
		}

		const modResult = await moderateUsername(usernameStr, env);
		if (modResult.result === 'REJECT') {
			return json({ error: 'Username rejected by moderation. Please choose a different name.' }, 400);
		}

		newName = usernameStr;
		shouldUpdateName = true;
	}

	if (payload.avatarUrl !== undefined) {
		if (avatarUrl === null) return json({ error: 'Invalid avatar URL' }, 400);
		await env.DB.prepare(`UPDATE users SET avatar_url = ?, updated_at = ? WHERE id = ?`)
			.bind(avatarUrl, Date.now(), session.user_id)
			.run();
	}

	if (shouldUpdateName) {
		await env.DB.prepare(`UPDATE users SET name = ?, updated_at = ? WHERE id = ?`)
			.bind(newName, Date.now(), session.user_id)
			.run();
	}

	const updated = await env.DB.prepare(
		`SELECT id, login, name, avatar_url, profile_url FROM users WHERE id = ? LIMIT 1`
	)
		.bind(session.user_id)
		.first<{ id: string; login: string; name: string | null; avatar_url: string | null; profile_url: string | null }>();

	if (!updated) return json({ error: 'User not found' }, 404);

	return json({
		user: {
			id: updated.id,
			login: updated.login,
			name: updated.name,
			avatarUrl: updated.avatar_url,
			profileUrl: updated.profile_url,
		},
	});
}

export async function handleLogout(request: Request, env: Env): Promise<Response> {
	const token = bearerToken(request);
	if (!token) return json({ error: 'Unauthorized' }, 401);
	await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(token).run();
	return json({ ok: true }, 200);
}

export async function handleEmailSend(request: Request, env: Env): Promise<Response> {
	const ip = getClientIp(request);

	const ipKey = `rate_limit:ip:${ip}`;
	const ipCount = await env.RATE_LIMIT_KV.get(ipKey);
	if (ipCount && parseInt(ipCount) >= 5) {
		return json({ error: 'Too many requests' }, 429);
	}

	if (!env.RESEND_API_KEY) {
		return json({ error: 'Email service is not configured' }, 500);
	}

	let payload: { email?: unknown; turnstileToken?: unknown };
	try {
		payload = (await request.json()) as { email?: unknown; turnstileToken?: unknown };
	} catch {
		return json({ error: 'Invalid JSON' }, 400);
	}

	const email = typeof payload.email === 'string' ? payload.email.trim().toLowerCase() : '';
	const turnstileToken = typeof payload.turnstileToken === 'string' ? payload.turnstileToken : '';

	if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
		return json({ error: 'Invalid email address' }, 400);
	}

	if (env.TURNSTILE_SECRET_KEY) {
		if (!turnstileToken) return json({ error: 'Captcha required' }, 400);
		const turnstileValid = await verifyTurnstile(turnstileToken, env.TURNSTILE_SECRET_KEY, ip);
		if (!turnstileValid) return json({ error: 'Invalid captcha' }, 400);
	}

	const emailKey = `rate_limit:email:${email}`;
	const lastSent = await env.RATE_LIMIT_KV.get(emailKey);
	if (lastSent) {
		return json({ ok: true, message: 'Login email already sent, please check your inbox' });
	}

	const existingToken = await env.DB.prepare(
		`SELECT token FROM email_logins WHERE email = ? AND used = 0 AND expires_at > ? LIMIT 1`
	)
		.bind(email, Date.now())
		.first<{ token: string }>();

	let token: string;

	if (existingToken) {
		token = existingToken.token;
	} else {
		token = randomBase64Url(32);
		const tokenId = `em_${randomBase64Url(12)}`;
		const now = Date.now();
		const expiresAt = now + 15 * 60 * 1000;

		await env.DB.prepare(
			`INSERT INTO email_logins (id, email, token, expires_at, used, created_at)
			 VALUES (?, ?, ?, ?, 0, ?)`
		)
			.bind(tokenId, email, token, expiresAt, now)
			.run();
	}

	const baseUrl = env.BASE_URL || 'https://api.danarnoux.com';
	const loginUrl = `${baseUrl}/api/auth/email/verify?token=${encodeURIComponent(token)}`;
	const htmlEmail = buildLoginEmailHtml(loginUrl, email);

	try {
		const { Resend } = await import('resend');
		const resend = new Resend(env.RESEND_API_KEY);

		await resend.emails.send({
			from: 'Dan\'s Blog Login <login@mail.danarnoux.com>',
			to: [email],
			subject: '🔐 Sign in to Dan\'s Blog',
			html: htmlEmail,
		});
	} catch (error) {
		console.error('Failed to send email:', error);
		return json({ error: 'Failed to send email' }, 500);
	}

	const currentCount = ipCount ? parseInt(ipCount) : 0;
	await env.RATE_LIMIT_KV.put(ipKey, String(currentCount + 1), { expirationTtl: 60 });
	await env.RATE_LIMIT_KV.put(emailKey, '1', { expirationTtl: 60 });

	await new Promise(resolve => setTimeout(resolve, 300 + Math.random() * 500));

	return json({ ok: true, message: 'Login email sent' });
}

export async function handleEmailVerify(request: Request, env: Env): Promise<Response> {
	const url = new URL(request.url);
	const token = request.method === 'POST'
		? await readEmailVerifyTokenFromPost(request)
		: url.searchParams.get('token') ?? '';

	if (!token) return json({ error: 'Missing token' }, 400);

	const row = await env.DB.prepare(
		`SELECT id, email, expires_at, used FROM email_logins WHERE token = ? LIMIT 1`
	)
		.bind(token)
		.first<{ id: string; email: string; expires_at: number; used: number }>();

	if (!row) return emailVerifyMessagePage('Invalid token.', 400);
	if (row.used) return emailVerifyMessagePage('This login link has already been used.', 400);
	if (Number(row.expires_at) <= Date.now()) return emailVerifyMessagePage('This login link has expired.', 400);
	if (request.method === 'GET') return emailVerifyConfirmPage(token);

	const consumeResult = await env.DB.prepare(
		`UPDATE email_logins SET used = 1 WHERE token = ? AND used = 0 AND expires_at > ?`
	)
		.bind(token, Date.now())
		.run();

	const consumed = Number(consumeResult.meta?.changes ?? 0) === 1;

	if (!consumed) {
		const latestRow = await env.DB.prepare(
			`SELECT id, email, expires_at, used FROM email_logins WHERE token = ? LIMIT 1`
		)
			.bind(token)
			.first<{ id: string; email: string; expires_at: number; used: number }>();

		if (!latestRow) return emailVerifyMessagePage('Link invalid.', 400);
		if (latestRow.used) return emailVerifyMessagePage('Link already used.', 400);
		if (Number(latestRow.expires_at) <= Date.now()) return emailVerifyMessagePage('Link expired.', 400);
		return emailVerifyMessagePage('Sign in failed.', 400);
	}

	const email = row.email;
	const now = Date.now();
	const generatedUserId = `email:${email}`;

	const existingUser = await env.DB.prepare('SELECT id FROM users WHERE id = ? LIMIT 1')
		.bind(generatedUserId)
		.first<{ id: string }>();

	const existingEmailOwner = await env.DB.prepare('SELECT id FROM users WHERE email = ? LIMIT 1')
		.bind(email)
		.first<{ id: string }>();

	const userId = existingUser?.id ?? generatedUserId;

	if (!existingUser) {
		if (existingEmailOwner && existingEmailOwner.id !== generatedUserId && !existingEmailOwner.id.startsWith('email:')) {
			await env.DB.prepare(`UPDATE users SET email = NULL, email_verified = 0, updated_at = ? WHERE id = ?`)
				.bind(now, existingEmailOwner.id)
				.run();
		}

		const login = email.split('@')[0];
		const syntheticGithubId = syntheticGithubIdForKey(`email:${email}`);
		await env.DB.prepare(
			`INSERT INTO users (id, github_id, login, name, email, email_verified, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, 1, ?, ?)`
		)
			.bind(generatedUserId, syntheticGithubId, login, null, email, now, now)
			.run();
	} else {
		await env.DB.prepare(`UPDATE users SET email = ?, email_verified = 1, updated_at = ? WHERE id = ?`)
			.bind(email, now, userId)
			.run();
	}

	const sessionTtlSeconds = clampInt(env.SESSION_TTL_SECONDS, 300, 365 * 24 * 3600, 30 * 24 * 3600);
	const sessionToken = randomBase64Url(32);
	const expiresAt = now + sessionTtlSeconds * 1000;

	await env.DB.prepare(
		`INSERT INTO sessions (id, user_id, created_at, expires_at, ip, user_agent)
		 VALUES (?, ?, ?, ?, ?, ?)`
	)
		.bind(sessionToken, userId, now, expiresAt, clientIp(request), (request.headers.get('user-agent') ?? '').slice(0, 256))
		.run();

	const redirectTo = `${FRONTEND_URL}/#token=${encodeURIComponent(sessionToken)}`;
	return new Response(null, { status: 302, headers: { location: redirectTo, 'cache-control': 'no-store' } });
}

export async function handleDevLogin(request: Request, env: Env): Promise<Response> {
	if (!env.DEV) return json({ error: 'Not Found' }, 404);

	let payload: { login?: unknown; name?: unknown };
	try {
		payload = (await request.json()) as { login?: unknown; name?: unknown };
	} catch {
		return json({ error: 'Invalid JSON' }, 400);
	}

	const login = typeof payload.login === 'string' ? payload.login.trim() : 'dev_user';
	const name = typeof payload.name === 'string' ? payload.name.trim() : 'Dev User';

	const userId = `dev:${login}`;
	const now = Date.now();
	const syntheticGithubId = syntheticGithubIdForKey(userId);

	await env.DB.prepare(
		`INSERT INTO users (id, github_id, login, name, avatar_url, profile_url, created_at, updated_at)
		 VALUES (?, ?, ?, ?, NULL, NULL, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET name = ?, updated_at = ?`
	)
		.bind(userId, syntheticGithubId, login, name, now, now, name, now)
		.run();

	const sessionToken = randomBase64Url(32);
	const sessionTtlSeconds = 30 * 24 * 3600;
	const expiresAt = now + sessionTtlSeconds * 1000;

	await env.DB.prepare(
		`INSERT INTO sessions (id, user_id, created_at, expires_at, ip, user_agent)
		 VALUES (?, ?, ?, ?, ?, ?)`
	)
		.bind(sessionToken, userId, now, expiresAt, '127.0.0.1', 'dev')
		.run();

	return json({ ok: true, token: sessionToken });
}

// --- Internal helpers ---

async function verifyTurnstile(token: string, secret: string, remoteIp?: string): Promise<boolean> {
	try {
		const formData = new FormData();
		formData.append('response', token);
		formData.append('secret', secret);
		if (remoteIp) formData.append('remoteip', remoteIp);

		const result = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
			method: 'POST',
			body: formData,
		});

		const outcome = (await result.json()) as { success: boolean };
		return outcome.success === true;
	} catch {
		return false;
	}
}

function redirectWithClearedOAuth(returnTo: string): Response {
	const location = returnTo.includes('danarnoux.com') ? returnTo : FRONTEND_URL;
	const headers = new Headers({ location, 'cache-control': 'no-store' });
	headers.append('set-cookie', clearCookie(STATE_COOKIE));
	headers.append('set-cookie', clearCookie(VERIFIER_COOKIE));
	headers.append('set-cookie', clearCookie(RETURN_TO_COOKIE));
	return new Response(null, { status: 302, headers });
}

async function readEmailVerifyTokenFromPost(request: Request): Promise<string> {
	const contentType = request.headers.get('content-type') ?? '';

	if (contentType.includes('application/x-www-form-urlencoded') || contentType.includes('multipart/form-data')) {
		const form = await request.formData();
		const token = form.get('token');
		return typeof token === 'string' ? token : '';
	}

	if (contentType.includes('application/json')) {
		try {
			const payload = (await request.json()) as { token?: unknown };
			return typeof payload.token === 'string' ? payload.token : '';
		} catch {
			return '';
		}
	}

	try {
		const body = await request.text();
		const params = new URLSearchParams(body);
		return params.get('token') ?? '';
	} catch {
		return '';
	}
}

function buildLoginEmailHtml(loginUrl: string, email: string): string {
	return `
<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; background-color: #f4f4f5; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
	<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #f4f4f5; padding: 48px 20px;">
		<tr>
			<td align="center">
				<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width: 440px; background-color: #ffffff; border-radius: 16px; border: 1px solid #e7e2d4; box-shadow: 0 18px 48px rgba(24,24,27,0.08); overflow: hidden;">
					<!-- Gold hairline accent -->
					<tr>
						<td style="height: 3px; background: linear-gradient(90deg, #b47e24, #e2be6e, #966616); font-size: 0; line-height: 0;">&nbsp;</td>
					</tr>
					<!-- Header -->
					<tr>
						<td style="padding: 32px 32px 0; text-align: center;">
							<div style="display: inline-block; padding: 5px 12px; border: 1px solid #ece6d6; border-radius: 999px; background-color: #faf7f0; font-size: 11px; font-weight: 700; letter-spacing: 0.14em; text-transform: uppercase; color: #a8761e;">Secure Sign In</div>
							<h1 style="margin: 18px 0 0; font-size: 26px; font-weight: 600; letter-spacing: -0.01em; color: #18181b;">Dan<span style="color: #b47e24;">&rsquo;</span>s <span style="font-style: italic; font-weight: 500; color: #52525b;">Blog</span></h1>
							<div style="margin: 14px auto 0; width: 40px; height: 1px; background: linear-gradient(90deg, rgba(180,126,36,0), #b47e24, rgba(180,126,36,0));">&nbsp;</div>
						</td>
					</tr>
					<!-- Content -->
					<tr>
						<td style="padding: 22px 32px 26px; text-align: center;">
							<p style="margin: 0 0 22px; font-size: 15px; color: #52525b; line-height: 1.6;">
								Tap the button below to sign in. This magic link works once and only for you.
							</p>
							<!-- CTA Button -->
							<div style="padding: 0 0 22px;">
								<a href="${loginUrl}" style="display: inline-block; padding: 13px 30px; font-size: 15px; font-weight: 600; color: #ffffff; background-color: #18181b; text-decoration: none; border-radius: 12px; box-shadow: 0 10px 22px rgba(24,24,27,0.18);">Sign in &rarr;</a>
							</div>
							<!-- Email info -->
							<p style="margin: 0; font-size: 13px; color: #71717a; line-height: 1.5;">
								Requested for <span style="font-weight: 600; color: #3f3f46;">${escapeHtml(email)}</span>
							</p>
						</td>
					</tr>
					<!-- Footer -->
					<tr>
						<td style="padding: 16px 32px; background-color: #faf7f0; border-top: 1px solid #ece6d6;">
							<p style="margin: 0; font-size: 12px; color: #a1a1aa; text-align: center;">
								Link expires in 15 minutes
							</p>
						</td>
					</tr>
				</table>
				<p style="margin: 20px 0 0; font-size: 11px; color: #a1a1aa; text-align: center;">
					Didn't request this? You can safely ignore this email.
				</p>
			</td>
		</tr>
	</table>
</body>
</html>
	`;
}

function emailVerifyConfirmPage(token: string): Response {
	const html = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>Confirm Sign In</title>
</head>
<body style="margin:0;font-family:Inter,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:radial-gradient(circle at top,#fafaf9 0,#f4f4f5 42%,#ededed 100%);color:#18181b;">
	<div style="min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;">
		<div style="position:relative;width:100%;max-width:460px;background:rgba(255,255,255,0.92);border:1px solid #e4e4e7;border-radius:20px;padding:32px;box-sizing:border-box;box-shadow:0 24px 80px rgba(24,24,27,0.08);backdrop-filter:blur(10px);">
			<div style="display:inline-flex;align-items:center;gap:8px;padding:6px 10px;border:1px solid #e4e4e7;border-radius:999px;background:#fafafa;color:#52525b;font-size:12px;font-weight:600;letter-spacing:0.02em;">Dan's Blog</div>
			<h1 style="margin:18px 0 10px;font-size:30px;line-height:1.1;letter-spacing:-0.03em;">Finish sign in.</h1>
			<p style="margin:0 0 22px;line-height:1.7;color:#52525b;font-size:15px;">One more step. Then you're in.</p>
			<div style="margin:0 0 20px;padding:14px 16px;border-radius:14px;background:#fafafa;border:1px solid #e4e4e7;">
				<div style="font-size:12px;font-weight:600;letter-spacing:0.03em;text-transform:uppercase;color:#71717a;">Secure Sign In</div>
				<div style="margin-top:8px;font-size:14px;line-height:1.6;color:#3f3f46;">Press the button to continue to <span style="font-weight:600;color:#18181b;">danarnoux.com</span>.</div>
			</div>
			<form method="post" action="/api/auth/email/verify" style="margin:0;">
				<input type="hidden" name="token" value="${escapeHtml(token)}">
				<button type="submit" style="width:100%;border:0;border-radius:12px;background:#18181b;color:#fff;padding:14px 18px;font-size:14px;font-weight:600;letter-spacing:0.01em;cursor:pointer;box-shadow:0 12px 28px rgba(24,24,27,0.18);">Sign in to Dan's Blog</button>
			</form>
			<p style="margin:16px 0 0;color:#71717a;font-size:12px;line-height:1.5;">This helps block automatic email scans.</p>
			<a href="${FRONTEND_URL}" style="display:inline-block;margin-top:14px;color:#52525b;font-size:13px;text-decoration:none;">Back to homepage</a>
		</div>
	</div>
</body>
</html>`;

	return new Response(html, {
		status: 200,
		headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' },
	});
}

function emailVerifyMessagePage(message: string, status: number): Response {
	const html = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>Email Sign In</title>
</head>
<body style="margin:0;font-family:Inter,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:linear-gradient(180deg,#fafafa 0,#f4f4f5 100%);color:#18181b;">
	<div style="min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;">
		<div style="width:100%;max-width:460px;background:#fff;border:1px solid #e4e4e7;border-radius:20px;padding:32px;box-sizing:border-box;text-align:center;box-shadow:0 24px 80px rgba(24,24,27,0.08);">
			<div style="display:inline-flex;width:52px;height:52px;align-items:center;justify-content:center;border-radius:999px;background:#18181b;color:#fff;font-size:22px;font-weight:700;">i</div>
			<h1 style="margin:18px 0 10px;font-size:30px;line-height:1.1;letter-spacing:-0.03em;">Can't sign in.</h1>
			<p style="margin:0 0 22px;line-height:1.7;color:#52525b;font-size:15px;">${escapeHtml(message)}</p>
			<a href="${FRONTEND_URL}" style="display:inline-block;border-radius:12px;background:#18181b;color:#fff;padding:14px 18px;font-size:14px;font-weight:600;text-decoration:none;box-shadow:0 12px 28px rgba(24,24,27,0.18);">Return to homepage</a>
		</div>
	</div>
</body>
</html>`;

	return new Response(html, {
		status,
		headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' },
	});
}
