/**
 * Content Moderation Rules
 * Separate file for easy rule management
 */

export type ModerationResult = 'ALLOW' | 'REVIEW' | 'REJECT';

// ============================================
// Technical Attack Patterns (Rule-based)
// Only blocks clear attack patterns, not normal words
// ============================================

// SQL injection - only block clear attack patterns, not normal words like "select"
export const SQL_INJECTION_PATTERNS = [
	/;\s*(drop|delete|update|insert|alter|create|truncate)/i,
	/(or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?/i,  // or 1=1, and 1=1
	/union\s+(all\s+)?select/i,
	/--\s*$/m,
	/;\s*$/m,
	/\bexec\s*\(/i,
	/\bexecute\s*\(/i,
	/\bxpa_/i,
	/\bsp_/i,
];

// XSS patterns - block HTML/JS injection tags, not normal words
export const XSS_PATTERNS = [
	/<script/i,
	/javascript:/i,
	/on\w+\s*=/i,          // onerror=, onclick=, onload=, etc.
	/<iframe/i,
	/<object/i,
	/<embed/i,
	/<svg/i,
	/data:/i,              // data: URL with content
	/vbscript:/i,
];

// ============================================
// English Vulgar Abbreviations (Rule-based)
// ============================================

export const VULGAR_ABBREVIATIONS = [
	/\bkys\b/i,
	/\bstfu\b/i,
	/\bf+u+c+k+\b/i,
	/\bb+i+t+c+h\b/i,
	/\bass\b(?!ess|ign|ume|ert|ist|ociat|embl)/i,
	/\bd+i+c+k\b/i,
	/\bp+u+s+s+y\b/i,
	/\bn+i+g+g+e+r\b/i,
	/\bfml\b/i,
	/\bgtfo\b/i,
];

// ============================================
// Chinese Profanity Patterns (Rule-based)
// 只匹配「明确指向性辱骂」的固定词组。
// 严禁用字符集 [..] 表达「多选词」——那会把集合里的每个单字逐字命中
// （旧版 [尼玛的] 的「的」、[屄婊子] 的「子」、[废物垃圾] 的「物」、
//  [脑残智障弱智] 的「智/脑/弱」都是高频字），导致正常中文被整片误杀。
// 用 /i 不用 /g：模块级常量 + .test() 复用时，/g 的 lastIndex 会残留并造成间歇性漏判。
// ============================================

export const CHINESE_PROFANITY_PATTERNS = [
	/操你|草你|日你妈|干你娘|草泥马|cnm\b/i,        // 指向性辱骂
	/他妈的|去你妈的|尼玛|你妈死/i,                  // 国骂
	/傻逼|傻屄|煞笔/i,                              // 傻逼及变体
	/滚你妈|去死吧|死全家|nmsl\b/i,                 // 诅咒
	/王八蛋|王八羔子|狗日的|狗娘养的/i,             // 复合脏词
	/婊子|贱人|贱货|骚货/i,                         // 侮辱
	/畜生|畜牲|人渣/i,                              // 侮辱
];

// ============================================
// 需「转待审」的可疑信号（偏严：宁可错杀）
// 命中这些不直接放行、也不直接拒，而是 REVIEW → 进 pending，由博主邮件一键放行/拒绝。
// 链接/拉私域/联系方式属确定性可疑信号；轻度贬损词语境依赖，交人工定夺而非误杀。
// 注意：明确攻击/脏话已在上面 REJECT，这里只接住「拿不准」的灰色地带。
// ============================================

export const REVIEW_PATTERNS = [
	/https?:\/\//i,                                                                 // 明确链接
	/www\.[a-z0-9-]+\.[a-z]{2,}/i,                                                  // www 域名
	/(微信|薇信|威信|加\s*我|weixin|wechat|\bvx\b|\bv信\b|QQ\s*群|企鹅群|telegram|电报|加\s*群|私聊|加个?好友|扫码)/i, // 拉私域/联系方式
	/1[3-9]\d{9}/,                                                                  // 疑似手机号
	/(垃圾|废物|辣鸡|垃圾玩意|拉胯|水货|low\s*爆|弱爆|菜得|菜的)/i,                    // 轻度贬损/嘲讽（语境依赖，送人工）
];

// ============================================
// AI Moderation (handled by callAI)
// ============================================
// The AI layer handles semantic analysis beyond these rules

// Content length limits (apply to all content)
export const MAX_CONTENT_LENGTH = 5000;
export const MAX_REPEAT_CHARS = 10;

/**
 * Technical attack detection - Layer 1 of moderation
 * 返回 ALLOW（进 AI 语义层）/ REVIEW（转人工待审）/ REJECT（直接拒）
 */
export function ruleFilter(content: string): { result: ModerationResult; reason?: string } {
	// Check for SQL injection
	for (const pattern of SQL_INJECTION_PATTERNS) {
		if (pattern.test(content)) {
			return { result: 'REJECT', reason: 'Invalid input pattern detected' };
		}
	}

	// Check for XSS
	for (const pattern of XSS_PATTERNS) {
		if (pattern.test(content)) {
			return { result: 'REJECT', reason: 'Invalid input pattern detected' };
		}
	}

	// Check for English vulgar abbreviations (held for review)
	for (const pattern of VULGAR_ABBREVIATIONS) {
		if (pattern.test(content)) {
			return { result: 'REVIEW', reason: 'Content contains inappropriate language' };
		}
	}

	// Check for Chinese profanity (held for review)
	for (const pattern of CHINESE_PROFANITY_PATTERNS) {
		if (pattern.test(content)) {
			return { result: 'REVIEW', reason: 'Content contains inappropriate language' };
		}
	}

	// Check for excessive length
	if (content.length > MAX_CONTENT_LENGTH) {
		return { result: 'REJECT', reason: 'Content exceeds maximum length' };
	}

	// Check for repetitive characters (spam indicator)
	if (new RegExp(`(.)\\1{${MAX_REPEAT_CHARS},}`).test(content)) {
		return { result: 'REJECT', reason: 'Invalid content pattern detected' };
	}

	// 可疑信号 → 转人工待审（REVIEW）：偏严，宁可错杀（博主邮件一键放行）
	for (const pattern of REVIEW_PATTERNS) {
		if (pattern.test(content)) {
			return { result: 'REVIEW', reason: 'Held for manual review' };
		}
	}

	// Content passes technical checks - AI will handle semantic analysis
	return { result: 'ALLOW' };
}
