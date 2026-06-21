import type { Env } from './types';
import { ruleFilter, type ModerationResult } from './moderation-rules';

export type { ModerationResult };

// 审核模型：Qwen3-30B-A3B（MoE，中文母语级理解，价格低于旧的 llama-3-8b）。
// 注意：Qwen3 是 reasoning 模型，prompt 末尾用 /no_think 关闭思考链；
// parseVerdict 再取「最后一次出现的判定词」做双保险，即便偶发思考链也不影响结论。
const MOD_MODEL = '@cf/qwen/qwen3-30b-a3b-fp8';

// 缓存键版本：审核规则/提示词/模型变更后，递增此版本即可让旧的（可能误判的）缓存立即失效。
const CACHE_VERSION = 'v3';

async function hashContent(content: string): Promise<string> {
	const encoder = new TextEncoder();
	const data = encoder.encode(content);
	const hashBuffer = await crypto.subtle.digest('SHA-256', data);
	const hashArray = Array.from(new Uint8Array(hashBuffer));
	return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function checkCache(contentHash: string, env: Env): Promise<ModerationResult | null> {
	const cached = await env.MODERATION_KV.get(`mod:${CACHE_VERSION}:${contentHash}`);
	if (cached) return cached as ModerationResult;
	return null;
}

async function cacheResult(contentHash: string, result: ModerationResult, env: Env): Promise<void> {
	await env.MODERATION_KV.put(`mod:${CACHE_VERSION}:${contentHash}`, result, { expirationTtl: 86400 });
}

/**
 * 鲁棒解析模型输出：取最后一次出现的 ALLOW/REVIEW/REJECT。
 * reasoning 模型即便输出思考过程，结论也在最后；解析不到时 fail-closed（REVIEW，转人工待审）。
 */
function parseVerdict(response: string): ModerationResult {
	const text = (response || '').toUpperCase();
	const matches = text.match(/\b(ALLOW|REVIEW|REJECT)\b/g);
	if (matches && matches.length > 0) {
		return matches[matches.length - 1] as ModerationResult;
	}
	return 'REVIEW';
}

// 偏严三态标准：明确善意→ALLOW；可疑/灰色/拿不准→REVIEW（转人工待审，不公开）；明确恶意→REJECT。
// 核心：拿不准一律 REVIEW —— 既不放过可疑，又不误杀正常（博主邮件一键放行）。
const COMMENT_SYSTEM_PROMPT = `You are the comment moderator for a personal tech blog. The owner prefers a STRICT policy: when in doubt, HOLD FOR REVIEW rather than auto-publish. Judge the message's intent as a whole — do NOT keyword-match. Messages may be Chinese or English. Reply with EXACTLY one word: ALLOW, REVIEW, or REJECT.

ALLOW — clearly good-faith, safe to publish immediately:
- Genuine questions, technical discussion, helpful suggestions
- Sincere praise or thanks ("great post", "谢谢", "很棒", "学到了")
- Constructive or neutral criticism ("I think this part could be clearer", "这里写得不够清楚")
- Technical terms that only look violent out of context: "rm -rf", "kill the process", "kill -9", "DROP TABLE", "删库"

REVIEW — suspicious, borderline, profanity, or insults (hold for the owner to check):
- Sarcasm, mockery, passive-aggressive or ambiguous tone
- Mild insults / belittling aimed at someone ("垃圾", "废物", "辣鸡", "水平真差", "菜")
- Personal attacks, insults, swearing, profanity, harassment, hate speech, slurs ("操你", "傻逼", "fuck", "bitch", etc.)
- Contains a URL / external link, or anything that reads like promotion (unless it is obvious commercial spam, which should be REJECT)
- Tries to move off-platform (加微信 / QQ / Telegram / "私聊")
- Low-effort filler, pure emoji, or generic marketing-sounding text
- Emotional venting without a clear attack
- Too short or vague to judge intent confidently

REJECT — clearly commercial spam or dangerous content, block outright:
- Obvious commercial spam, ads, scams, gambling/porn promotion
- Sexually explicit content
- Explicit threats of violence

Tie-break — the owner prefers a STRICT policy and false positives are cheap (REVIEW merely holds it for the owner to release): ERR ON THE SIDE OF REVIEW. Only choose ALLOW when the message is clearly friendly/on-topic with NO promotional, contact-sharing, link, or hostile signal. Any doubt → REVIEW. When unsure between REVIEW and REJECT, choose REVIEW.

Output ONLY one word: ALLOW, REVIEW, or REJECT. /no_think`;

async function callAI(content: string, env: Env): Promise<ModerationResult> {
	try {
		const result = await env.AI.run(MOD_MODEL, {
			messages: [
				{ role: 'system', content: COMMENT_SYSTEM_PROMPT },
				{ role: 'user', content: `Message to moderate (judge intent, reply one word):\n\n${content}\n\n/no_think` },
			],
			temperature: 0,
			max_tokens: 512,
		});
		return parseVerdict((result as { response: string }).response);
	} catch (error) {
		console.error('AI moderation failed:', error);
		return 'REVIEW'; // 评论：AI 故障转待审（有 pending 承载，宁可博主多看一眼也不漏）
	}
}

export async function moderateContent(
	content: string,
	env: Env
): Promise<{ result: ModerationResult; reason?: string; cached?: boolean }> {
	const ruleResult = ruleFilter(content);
	if (ruleResult.result !== 'ALLOW') return ruleResult;

	const contentHash = await hashContent(content);
	const cachedResult = await checkCache(contentHash, env);
	if (cachedResult) return { result: cachedResult, cached: true };

	const aiResult = await callAI(content, env);
	await cacheResult(contentHash, aiResult, env);

	return { result: aiResult };
}

// 用户名无 pending 承载：偏严，可疑直接 REJECT 让用户重选；只输出 ALLOW / REJECT。
const USERNAME_SYSTEM_PROMPT = `You moderate usernames for a personal blog. The owner prefers strict usernames. Reply with EXACTLY one word: ALLOW or REJECT.

ALLOW: normal names or nicknames, English or Chinese ("John", "dandan", "小明", "测试", "dan").

REJECT: offensive slurs, profanity, sexual terms; impersonation of the site owner/staff ("admin", "管理员", "站长", "客服"); spam/ads or embedded URLs; contact handles; or nonsensical / very long strings.

When in doubt, REJECT and let the user pick another. Output ONLY ALLOW or REJECT. /no_think`;

async function callAIForUsername(username: string, env: Env): Promise<ModerationResult> {
	try {
		const result = await env.AI.run(MOD_MODEL, {
			messages: [
				{ role: 'system', content: USERNAME_SYSTEM_PROMPT },
				{ role: 'user', content: `Username to check:\n\n${username}\n\n/no_think` },
			],
			temperature: 0,
			max_tokens: 512,
		});
		return parseVerdict((result as { response: string }).response);
	} catch (error) {
		console.error('Username AI moderation failed:', error);
		return 'ALLOW'; // 用户名低风险：AI 故障时放行，避免阻塞正常改名
	}
}

export async function moderateUsername(
	username: string,
	env: Env
): Promise<{ result: ModerationResult; reason?: string }> {
	const ruleResult = ruleFilter(username);
	if (ruleResult.result !== 'ALLOW') return ruleResult;

	const aiResult = await callAIForUsername(username, env);
	return { result: aiResult };
}
