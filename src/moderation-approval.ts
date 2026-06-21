import type { Env } from './types';
import { escapeHtml } from './utils';

// ============================================================
// 评论审批工作流：可疑评论进入 pending 后，给博主发一封带签名的「批准/拒绝」
// 链接邮件。博主点链接 -> 确认页（防邮件客户端预取误触发）-> 再点确认才改状态。
// 链接用 HMAC-SHA256 签名，无密钥无法伪造；收件箱与密钥均来自加密的 env。
// ============================================================

// 对外公开的发信身份（非私人邮箱，绑定 Resend 验证域），可留在源码。
const FROM = "Tavric's Blog <onboarding@resend.dev>";

function base(env: Env): string {
	return env.BASE_URL || 'https://tavricccc-worker.tavric.workers.dev';
}

function moderationSecret(env: Env): string {
	// 缺省回退 OAuth secret，免去额外配置；想更规范可单独 `wrangler secret put MODERATION_SECRET`。
	return env.MODERATION_SECRET || env.GITHUB_CLIENT_SECRET || '';
}

function toBase64Url(bytes: Uint8Array): string {
	let bin = '';
	for (const b of bytes) bin += String.fromCharCode(b);
	return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function sign(data: string, secret: string): Promise<string> {
	const key = await crypto.subtle.importKey(
		'raw',
		new TextEncoder().encode(secret),
		{ name: 'HMAC', hash: 'SHA-256' },
		false,
		['sign']
	);
	const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
	return toBase64Url(new Uint8Array(sig));
}

function safeEqual(a: string, b: string): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
	return diff === 0;
}

async function verifyToken(id: string, action: string, token: string, env: Env): Promise<boolean> {
	const secret = moderationSecret(env);
	if (!token || !secret) return false;
	const expected = await sign(`${id}:${action}`, secret);
	return safeEqual(expected, token);
}

const VALID_ACTIONS = new Set(['approve', 'reject']);

// ── 发送待审通知邮件（复用 Resend）────────────────────────
// 整段用 try/catch 兜住：签名/发信的任何失败都只记日志，绝不让评论提交因此 500。
export async function sendModerationEmail(
	env: Env,
	c: { id: string; body: string; author: string; postSlug: string }
): Promise<void> {
	try {
		const secret = moderationSecret(env);
		if (!secret) {
			console.warn('Moderation email skipped: no signing secret (MODERATION_SECRET / GITHUB_CLIENT_SECRET)');
			return;
		}

		const approveToken = await sign(`${c.id}:approve`, secret);
		const rejectToken = await sign(`${c.id}:reject`, secret);
		const link = (action: string, token: string) =>
			`${base(env)}/api/moderate?id=${encodeURIComponent(c.id)}&a=${action}&t=${token}`;
		const approveUrl = link('approve', approveToken);
		const rejectUrl = link('reject', rejectToken);

		const to = env.CONTACT_TO_EMAIL;
		if (!env.RESEND_API_KEY || !to) {
			console.warn('Moderation email skipped: RESEND_API_KEY or CONTACT_TO_EMAIL not configured');
			return;
		}

		const { Resend } = await import('resend');
		const resend = new Resend(env.RESEND_API_KEY);
		await resend.emails.send({
			from: FROM,
			to: [to],
			subject: `[待审] ${c.author} 的评论`,
			html: buildModerationEmailHtml(c, approveUrl, rejectUrl),
		});
	} catch (error) {
		console.error('Failed to send moderation email:', error);
	}
}

// ── GET /api/moderate?id=&a=&t= -> 验签后返回确认页 ────────
// 故意只「展示」不「执行」，避免邮件客户端预取链接时误把评论放行。
export async function handleModerationPage(request: Request, env: Env): Promise<Response> {
	const url = new URL(request.url);
	const id = url.searchParams.get('id') || '';
	const action = url.searchParams.get('a') || '';
	const token = url.searchParams.get('t') || '';

	if (!id || !VALID_ACTIONS.has(action)) return htmlResponse(pageShell('链接无效', '<p>缺少必要参数。</p>'), 400);
	if (!(await verifyToken(id, action, token, env))) {
		return htmlResponse(pageShell('校验失败', '<p>签名校验未通过，链接可能被篡改或密钥已变更。</p>'), 403);
	}

	const row = await env.DB.prepare(
		`SELECT c.body, c.status, c.post_slug, u.name, u.login
		 FROM comments c JOIN users u ON u.id = c.user_id WHERE c.id = ? LIMIT 1`
	).bind(id).first<{ body: string; status: string; post_slug: string; name: string | null; login: string }>();

	if (!row) return htmlResponse(pageShell('评论不存在', '<p>该评论可能已被删除。</p>'), 404);

	const author = escapeHtml(row.name || row.login || 'Anonymous');
	const isApprove = action === 'approve';
	const statusNote = row.status !== 'pending'
		? `<p style="color:#a16207;">注意：该评论当前状态为 <b>${escapeHtml(row.status)}</b>，并非待审。</p>`
		: '';

	const body = `
		${statusNote}
		<div class="meta">来自 <b>${author}</b> · 文章 <code>${escapeHtml(row.post_slug)}</code></div>
		<blockquote>${escapeHtml(row.body)}</blockquote>
		<p>确认要将这条评论标记为 <b>${isApprove ? '通过并公开' : '拒绝'}</b> 吗？</p>
		<form method="POST" action="${base(env)}/api/moderate/confirm">
			<input type="hidden" name="id" value="${escapeHtml(id)}">
			<input type="hidden" name="a" value="${escapeHtml(action)}">
			<input type="hidden" name="t" value="${escapeHtml(token)}">
			<button class="${isApprove ? 'ok' : 'no'}" type="submit">${isApprove ? '确认通过' : '确认拒绝'}</button>
		</form>`;
	return htmlResponse(pageShell(isApprove ? '通过评论' : '拒绝评论', body));
}

// ── POST /api/moderate/confirm -> 验签后改状态 ─────────────
export async function handleModerationConfirm(request: Request, env: Env): Promise<Response> {
	let form: FormData;
	try {
		form = await request.formData();
	} catch {
		return htmlResponse(pageShell('请求无效', '<p>无法解析表单。</p>'), 400);
	}
	const id = String(form.get('id') || '');
	const action = String(form.get('a') || '');
	const token = String(form.get('t') || '');

	if (!id || !VALID_ACTIONS.has(action)) return htmlResponse(pageShell('参数无效', '<p>缺少必要参数。</p>'), 400);
	if (!(await verifyToken(id, action, token, env))) {
		return htmlResponse(pageShell('校验失败', '<p>签名校验未通过。</p>'), 403);
	}

	const newStatus = action === 'approve' ? 'approved' : 'rejected';
	const result = await env.DB.prepare(
		`UPDATE comments SET status = ?, updated_at = ? WHERE id = ?`
	).bind(newStatus, Date.now(), id).run();

	if ((result.meta?.changes ?? 0) === 0) {
		return htmlResponse(pageShell('未改动', '<p>评论不存在或状态未变化。</p>'), 404);
	}

	const msg = action === 'approve'
		? '<p>评论已通过，现在会公开显示。</p>'
		: '<p>评论已拒绝，不会公开显示。</p>';
	return htmlResponse(pageShell('操作完成', msg));
}

// ── HTML 辅助 ─────────────────────────────────────────────
function htmlResponse(html: string, status = 200): Response {
	return new Response(html, {
		status,
		headers: { 'content-type': 'text/html; charset=utf-8', 'x-robots-tag': 'noindex, nofollow' },
	});
}

function pageShell(title: string, bodyHtml: string): string {
	return `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
	:root { color-scheme: light dark; }
	body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; padding:24px;
		font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:#fafafa; color:#18181b; }
	.card { max-width:480px; width:100%; background:#fff; border:1px solid #e4e4e7; border-radius:14px; padding:28px; }
	h1 { font-size:18px; margin:0 0 16px; }
	.meta { font-size:13px; color:#71717a; margin-bottom:10px; }
	blockquote { margin:0 0 16px; padding:14px 16px; background:#f4f4f5; border-left:3px solid #b47e24; border-radius:8px;
		white-space:pre-wrap; word-break:break-word; font-size:14px; line-height:1.6; }
	code { background:#f4f4f5; padding:1px 6px; border-radius:5px; font-size:12px; }
	button { width:100%; padding:12px; border:0; border-radius:10px; font-size:15px; font-weight:600; cursor:pointer; color:#fff; }
	button.ok { background:#16a34a; } button.no { background:#dc2626; }
	p { font-size:14px; line-height:1.6; }
	@media (prefers-color-scheme: dark) {
		body { background:#09090b; color:#e4e4e7; }
		.card { background:#18181b; border-color:#27272a; }
		blockquote, code { background:#27272a; }
	}
</style></head>
<body><div class="card"><h1>${escapeHtml(title)}</h1>${bodyHtml}</div></body></html>`;
}

function buildModerationEmailHtml(
	c: { body: string; author: string; postSlug: string },
	approveUrl: string,
	rejectUrl: string
): string {
	return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#f4f4f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f4f4f5;padding:40px 20px;"><tr><td align="center">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:460px;background:#ffffff;border-radius:10px;border:1px solid #e4e4e7;overflow:hidden;">
	<tr><td style="padding:24px 24px 8px;">
		<p style="margin:0;font-size:12px;color:#b47e24;font-weight:600;letter-spacing:.05em;text-transform:uppercase;">PENDING REVIEW</p>
		<h1 style="margin:6px 0 0;font-size:18px;color:#18181b;">有一条评论需要你确认</h1>
	</td></tr>
	<tr><td style="padding:12px 24px;">
		<p style="margin:0 0 6px;font-size:13px;color:#71717a;"><strong>${escapeHtml(c.author)}</strong> 评论于 <code style="background:#f4f4f5;padding:1px 6px;border-radius:4px;">${escapeHtml(c.postSlug)}</code></p>
		<div style="background:#f4f4f5;border-left:3px solid #b47e24;border-radius:8px;padding:14px 16px;margin-top:8px;">
			<p style="margin:0;font-size:14px;color:#18181b;line-height:1.6;white-space:pre-wrap;">${escapeHtml(c.body)}</p>
		</div>
	</td></tr>
	<tr><td style="padding:12px 24px 24px;">
		<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0"><tr>
			<td style="padding-right:6px;"><a href="${approveUrl}" style="display:block;text-align:center;padding:12px;background:#16a34a;color:#ffffff;text-decoration:none;border-radius:9px;font-size:15px;font-weight:600;">通过</a></td>
			<td style="padding-left:6px;"><a href="${rejectUrl}" style="display:block;text-align:center;padding:12px;background:#dc2626;color:#ffffff;text-decoration:none;border-radius:9px;font-size:15px;font-weight:600;">拒绝</a></td>
		</tr></table>
		<p style="margin:14px 0 0;font-size:12px;color:#a1a1aa;text-align:center;">点击后会打开确认页，再点一次确认才会生效。</p>
	</td></tr>
</table></td></tr></table></body></html>`;
}
