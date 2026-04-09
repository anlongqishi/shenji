import asyncio
from typing import List, Dict, Any
from loguru import logger
from curl_cffi import requests
import json
from urllib.parse import urlparse

class WaybackCDXExtractor:
    """
    OSINT 矩阵 20: Wayback Machine CDX API (历史镜像模板机)
    逆向提取大厂往年重大宣发的 URL 命名迭代模式，反哺 LLM 语义探测器。
    """
    def __init__(self):
        from core.utils import get_windows_proxy
        self.proxy_url = get_windows_proxy()
        # curl_cffi 的 proxies key 格式是 "https" 不是 "https://"，且不要 http/https 混合传参
        proxies = {"https": self.proxy_url} if self.proxy_url else None
        self.session = requests.AsyncSession(impersonate="chrome120", proxies=proxies)
        self.api_url = "http://web.archive.org/cdx/search/cdx"
        
    async def extract_from_query(self, cdx_query_url: str, name: str = "Unknown Probe") -> List[Dict[str, Any]]:
        # [HIGH-3 FIX] 强制升级为 HTTPS 截断中间人攻击
        if cdx_query_url.startswith("http://"):
            cdx_query_url = cdx_query_url.replace("http://", "https://", 1)
            
        logger.info(f"🕰️ [Wayback CDX] 访问档案馆 {name}: {cdx_query_url}")
        
        patterns = []
        try:
            # Wayback API 有硬性速率限制，防止被 Ban，每次调用强化延时 1.5 秒
            await asyncio.sleep(1.5)
            resp = await self.session.get(cdx_query_url, timeout=15)
            if resp.status_code == 429:
                logger.warning(f"[Wayback CDX] 触发 Rate Limit (429)，休眠后放弃当前请求")
                await asyncio.sleep(5)
                return patterns
            if resp.status_code != 200:
                logger.warning(f"[Wayback CDX] 接口受限: HTTP {resp.status_code}")
                return patterns
                
            data = resp.json()
            if not data or len(data) <= 1:
                logger.info(f"[Wayback CDX] {name} 未收录足够的老快照数据")
                return patterns
                
            headers = data[0]
            rows = data[1:]
            
            key_words = ['promo', 'bonus', 'act', 'campaign', 'free', 'developer']
            
            for r in rows:
                row_dict = dict(zip(headers, r))
                original_url = row_dict.get("original", "")
                url_path = urlparse(original_url).path.lower()
                
                # [DESIGN-3 FIX] 如果是针对泛域名的探针，依然需要保留关键字段过滤防垃圾填充
                if "matchType=domain" in cdx_query_url or "matchType=host" in cdx_query_url:
                    key_words = ['promo', 'bonus', 'act', 'campaign', 'free', 'developer', 'credit']
                    if not any(kw in url_path for kw in key_words) or len(url_path) <= 3:
                        continue

                patterns.append({
                    "url": original_url,
                    "timestamp": row_dict.get("timestamp"),
                    "digest": row_dict.get("digest")
                })
                    
            logger.success(f"[Wayback CDX] 从 {name} 挖掘出 {len(patterns)} 条有效的历史模板结构")
            return patterns
            
        except Exception as e:
            logger.error(f"[Wayback CDX] API 通信中断: {e}")
            return []

    async def close(self):
        await self.session.close()

if __name__ == "__main__":
    async def test():
        cdx = WaybackCDXExtractor()
        query = "https://web.archive.org/cdx/search/cdx?url=platform.openai.com/dashboard/billing*&output=json&limit=50&collapse=urlkey&filter=statuscode:200"
        res = await cdx.extract_from_query(query, "Test OpenAIBilling")
        for x in res[:10]:
            print(f"[{x['timestamp']}] {x['url']}")
        await cdx.close()
    asyncio.run(test())
