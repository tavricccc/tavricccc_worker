import type { Env } from './types';
import { json, getClientIp, escapeHtml } from './utils';
import { moderateContent } from './moderation';

export async function handleContact(request: Request, env: Env): Promise<Response> {
	const ip = getClientIp(request);

	const ipKey = `rate_limit:contact:ip:${ip}`;
	const ipCount = await env.RATE_LIMIT_KV.get(ipKey);
	if (ipCount && parseInt(ipCount) >= 3) {
		return json({ error: 'Too many requests, please try again later' }, 429);
	}

	if (!env.RESEND_API_KEY) {
		return json({ error: 'Contact form is not configured' }, 500);
	}

	let payload: { name?: unknown; email?: unknown; message?: unknown; turnstileToken?: unknown };
	try {
		payload = (await request.json()) as { name?: unknown; email?: unknown; message?: unknown; turnstileToken?: unknown };
	} catch {
		return json({ error: 'Invalid JSON' }, 400);
	}

	const name = typeof payload.name === 'string' ? payload.name.trim().slice(0, 100) : '';
	const email = typeof payload.email === 'string' ? payload.email.trim().toLowerCase() : '';
	const message = typeof payload.message === 'string' ? payload.message.trim().slice(0, 2000) : '';
	const turnstileToken = typeof payload.turnstileToken === 'string' ? payload.turnstileToken : '';

	if (!name || !email || !message) {
		return json({ error: 'Name, email and message are required' }, 400);
	}

	if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
		return json({ error: 'Invalid email address' }, 400);
	}

	if (message.length < 10) {
		return json({ error: 'Message is too short' }, 400);
	}

	if (env.TURNSTILE_SECRET_KEY) {
		if (!turnstileToken) return json({ error: 'Captcha required' }, 400);
		const turnstileValid = await verifyTurnstile(turnstileToken, env.TURNSTILE_SECRET_KEY, ip);
		if (!turnstileValid) return json({ error: 'Invalid captcha' }, 400);
	}

	// 联系表单只发到博主邮箱、不公开，故「只拦明显垃圾」：REJECT 不发；ALLOW/REVIEW 都发，
	// REVIEW 仅在邮件主题加 ⚠️ 提示博主留意（你本人就是最终审核者）。审核内容去掉 email 噪声。
	const modResult = await moderateContent(`${name}\n${message}`, env);
	if (modResult.result === 'REJECT') {
		return json({ error: 'Message rejected' }, 400);
	}
	const suspicious = modResult.result === 'REVIEW';

	const to = env.CONTACT_TO_EMAIL;
	if (!to) {
		console.error('Contact email skipped: CONTACT_TO_EMAIL not configured');
		return json({ error: 'Contact form is not configured' }, 500);
	}

	try {
		const { Resend } = await import('resend');
		const resend = new Resend(env.RESEND_API_KEY);

		const htmlContent = buildContactEmailHtml(name, email, message);

		await resend.emails.send({
			from: 'Tavric\'s Blog <onboarding@resend.dev>',
			to: [to],
			replyTo: email,
			subject: `${suspicious ? '⚠️ ' : '📬 '}${name} sent you a message`,
			html: htmlContent,
		});
	} catch (error) {
		console.error('Failed to send contact email:', error);
		return json({ error: 'Failed to send message' }, 500);
	}

	const currentCount = ipCount ? parseInt(ipCount) : 0;
	await env.RATE_LIMIT_KV.put(ipKey, String(currentCount + 1), { expirationTtl: 60 });

	return json({ ok: true, message: 'Message sent successfully' });
}

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

function buildContactEmailHtml(name: string, email: string, message: string): string {
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
				<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width: 420px; background-color: #ffffff; border-radius: 8px; border: 1px solid #e4e4e7;">
					<!-- Header -->
					<tr>
						<td style="padding: 24px 24px 0; text-align: center;">
							<h1 style="margin: 0; font-size: 20px; font-weight: 600; color: #18181b;">Dan's Blog</h1>
						</td>
					</tr>
					<!-- Content -->
					<tr>
						<td style="padding: 24px 24px 20px; text-align: center;">
							<p style="margin: 0 0 16px; font-size: 14px; color: #52525b; line-height: 1.5;">
								You received a new message:
							</p>
							<!-- Message preview -->
							<div style="background-color: #f4f4f5; border-radius: 8px; padding: 16px; margin-bottom: 16px; text-align: left;">
								<p style="margin: 0 0 8px; font-size: 13px; color: #71717a;">
									<strong>From:</strong> ${escapeHtml(name)} &lt;${escapeHtml(email)}&gt;
								</p>
								<p style="margin: 0; font-size: 14px; color: #18181b; line-height: 1.6; white-space: pre-wrap;">${escapeHtml(message)}</p>
							</div>
							<p style="margin: 0; font-size: 13px; color: #71717a;">
								Reply directly to this email to respond to ${escapeHtml(name)}.
							</p>
						</td>
					</tr>
					<!-- Footer -->
					<tr>
						<td style="padding: 16px 24px; background-color: #fafafa; border-top: 1px solid #e4e4e7; border-radius: 0 0 8px 8px;">
							<p style="margin: 0; font-size: 12px; color: #a1a1aa; text-align: center;">
								Sent from contact form
							</p>
						</td>
					</tr>
				</table>
			</td>
		</tr>
	</table>
</body>
</html>`;
}
