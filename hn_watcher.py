"""
雷达模块 - HackerNews Algolia 实时 API 监控
(OSINT 矩阵 维度 #闭门会议 — Show HN 极短时间窗体验码)

打法：
  1. 每 5 分钟拉取 hn.algolia.com 的 Show HN 最新条目
  2. 两个过滤层：
     a. 标题/文本含目标关键词（AI, API, credits, beta, free, inference...）
     b. 帖子来源与我们目标大厂相关联
  3. 拉取顶层评论列表，LLM 扫描评论区体验码/直达链接
  4. 通过 notifier 直接推送，T2C 极压

  注意：这个信号的黄金窗口期只有 20-30 分钟，必须用高频轮询
"""

import re
import asyncio
import httpx
import json
from loguru import logger
from typing import List, Dict, Optional

HN_FIREBASE_NEW = "https://hacker-news.firebaseio.com/v0/newstories.json"
HN_ITEM_BASE = "https://hacker-news.firebaseio.com/v0/item"

# 全局高优并发控制
HN_IMMEDIATE_CRAWL_SEMAPHORE = asyncio.Semaphore(3)

# ── 帖子标题关键词过滤 ───────────────────────────────────────────────────────
TITLE_KEYWORDS = re.compile(
    r"(free|credit|api|inference|beta|alpha|launch|token|gpu|compute|grant|llm|model|ai\b)",
    re.IGNORECASE
)

# ── 评论区体验码/直达链接特征 ────────────────────────────────────────────────
PROMO_CODE_PATTERN = re.compile(
    r"(promo|code|coupon|invite|credits?|voucher|dm me|reach out|first \d+|early access|beta)",
    re.IGNORECASE
)

# ── 目标大厂域名关键词（帖子 URL 或文本包含即加权）────────────────────────────
TARGET_DOMAIN_KEYWORDS = [
    "siliconflow", "deepseek", "groq", "together", "replicate",
    "huggingface", "cloudflare", "vercel", "neon", "anthropic",
    "openai", "mistral", "cohere",
]


class HNWatcher:
    """HackerNews Algolia 实时监控器"""

    def __init__(self):
        self.seen_story_ids: set = set()

    def _is_target_related(self, story: Dict) -> bool:
        text = f"{story.get('title', '')} {story.get('url', '')} {story.get('story_text', '')}".lower()
        return any(kw in text for kw in TARGET_DOMAIN_KEYWORDS)

    def _has_keywords(self, story: Dict) -> bool:
        title = story.get("title", "")
        return bool(TITLE_KEYWORDS.search(title))

    async def _fetch_firebase_new_stories(self, crawler) -> List[Dict]:
        """拉取最新故事并仅返回未见过的新帖详细信息"""
        try:
            result = await crawler.fetch(HN_FIREBASE_NEW)
            if not result.success:
                logger.warning(f"[HN Watcher] Firebase API failed: HTTP {result.status_code}")
                return []
            
            latest_ids = json.loads(result.content)
            if not isinstance(latest_ids, list):
                return []
                
            new_ids = [sid for sid in latest_ids[:100] if sid not in self.seen_story_ids] # 取前100，过滤已见过的
            stories = []
            
            # 这里并发不会过大，每30秒通常只有1~5个新帖
            for sid in new_ids:
                item_url = f"{HN_ITEM_BASE}/{sid}.json"
                item_res = await crawler.fetch(item_url)
                if item_res.success:
                    data = json.loads(item_res.content)
                    if data and isinstance(data, dict) and data.get("type") == "story":
                        stories.append(data)
                self.seen_story_ids.add(sid)
                
            return stories
        except Exception as e:
            logger.warning(f"[WARN] [HN Watcher] Firebase API failed: {e}")
            return []

    async def fetch_top_comments(self, crawler, story_id: int) -> List[str]:
        """获取帖子的顶层评论文本"""
        try:
            url = f"{HN_ITEM_BASE}/{story_id}.json"
            result = await crawler.fetch(url)
            if not result.success:
                return []
            story = json.loads(result.content)
            kid_ids = (story.get("kids") or [])[:10]  # 最多抓前 10 条评论

            comments = []
            for kid_id in kid_ids:
                url_kid = f"{HN_ITEM_BASE}/{kid_id}.json"
                cr_result = await crawler.fetch(url_kid)
                if not cr_result.success:
                    continue
                comment = json.loads(cr_result.content)
                text = comment.get("text", "") or ""
                # 只保留含宣传码特征的评论
                if PROMO_CODE_PATTERN.search(text):
                    # 剥离 HTML 标签
                    clean = re.sub(r"<[^>]+>", " ", text).strip()
                    comments.append(clean)
            return comments
        except Exception as e:
            logger.warning(f"[WARN] [HN Watcher] Comment fetch failed story={story_id}: {e}")
            return []

    async def poll_once(self) -> List[Dict]:
        hits = []
        from crawlers.anti_crawler import get_crawler
        crawler = get_crawler()
        
        # 改为 Firebase 增量拉取
        stories = await self._fetch_firebase_new_stories(crawler)
        for story in stories:
            sid = story.get("id")
            if not sid:
                continue

            # 使用组合判定：必须含有关键词，且强相关时提升权重
            if not self._has_keywords(story) and not self._is_target_related(story):
                continue

            # 计算信号强度：目标相关性强加权
            strength = 0.8 if self._is_target_related(story) else 0.5

            # 提取评论区体验码
            promo_comments = await self.fetch_top_comments(crawler, int(sid))

            # [P1 Fix] 净化真·目标产品链接
            target_url = story.get("url", "")
            if not target_url or "ycombinator.com" in target_url:
                # 尝试从正文内容里提取真正的外部展示链接
                urls = re.findall(r'https?://[^\s<>"]+', story.get("story_text", ""))
                if urls:
                    target_url = urls[0]  # First external product link
            
            if not target_url:
                target_url = f"https://news.ycombinator.com/item?id={sid}" # [P0 Fix] 强制保底降级

            logger.debug(
                f"[HIT] [HN Watcher] Show HN Hit: {story.get('title')} "
                f"| strength={strength} | promo_comments={len(promo_comments)}"
            )
            hits.append({
                "source": "hackernews_show_hn",
                "story_id": sid,
                "title": story.get("title", ""),
                "url": target_url,
                "hn_url": f"https://news.ycombinator.com/item?id={sid}",
                "action": "immediate_crawl", # 指示调度器进行插队抢入
                "points": story.get("score", 0),
                "message": f"HackerNews 高价值新帖：{story.get('title', '')}。包含宣传码特征的顶级评论数：{len(promo_comments)}",
                "signal_strength": strength,
                "promo_comments": promo_comments,
            })
        return hits


async def run_hn_watcher_loop(callback, interval_seconds: int = 30):
    """每 30 秒递增轮询 Firebase，这是获得首发码黄金窗口的最优频率"""
    watcher = HNWatcher()
    logger.info(f"[START] [HN Watcher] Guard running, interval: {interval_seconds}s (Firebase REST)")
    while True:
        hits = await watcher.poll_once()
        for hit in hits:
            try:
                # 接入 Semaphore 并在后台执行回调避免阻塞轮询环
                async def _throttled_dispatch(h=hit):
                    async with HN_IMMEDIATE_CRAWL_SEMAPHORE:
                        await callback(h)
                
                asyncio.create_task(_throttled_dispatch())
            except Exception as e:
                logger.error(f"[ERR] [HN Watcher] callback exception: {e}")
        await asyncio.sleep(interval_seconds)
