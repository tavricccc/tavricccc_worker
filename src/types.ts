export interface Env {
	DB: D1Database;
	IMAGES: R2Bucket;
	RATE_LIMITER?: DurableObjectNamespace;
	RATE_LIMIT_KV: KVNamespace;
	MODERATION_KV: KVNamespace;
	AI: Ai;
	GITHUB_CLIENT_ID: string;
	GITHUB_CLIENT_SECRET: string;
	PUBLIC_ALLOWED_ORIGIN?: string;
	SESSION_TTL_SECONDS?: string;
	RESEND_API_KEY?: string;
	BASE_URL?: string;
	TURNSTILE_SECRET_KEY?: string;
	DEV?: boolean;
	// 私人邮箱与签名密钥一律通过 `wrangler secret put` 注入，禁止写进 wrangler.toml / 源码（会进 git）。
	ADMIN_EMAILS?: string;       // 管理员登录邮箱（admin 权限校验）——原先明文在 wrangler.toml，已改 secret
	CONTACT_TO_EMAIL?: string;   // 博主收件箱：联系表单 + 评论待审通知都发到这里
	MODERATION_SECRET?: string;  // 审批链接 HMAC 签名密钥（缺省回退 GITHUB_CLIENT_SECRET）
}

export interface SessionRow {
	user_id: string;
	login: string;
	name: string | null;
	avatar_url: string | null;
	profile_url: string | null;
	expires_at: number;
}

export interface PostViewsRow {
	post_slug: string;
	views: number;
}

export const STATE_COOKIE = '__Secure-gh_state';
export const VERIFIER_COOKIE = '__Secure-gh_verifier';
export const RETURN_TO_COOKIE = '__Secure-gh_return_to';

export const OAUTH_COOKIE_TTL_SECONDS = 600;
export const RATE_LIMIT_PER_MIN = 10;
export const RATE_LIMIT_WINDOW_MS = 60_000;
export const COMMENT_MAX_LENGTH = 2000;
export const COMMENT_MIN_LENGTH = 1;
export const POST_SLUG_MAX_LENGTH = 180;
export const COMMENT_DAILY_LIMIT = 30;
export const FRONTEND_URL = 'https://danarnoux.com';
