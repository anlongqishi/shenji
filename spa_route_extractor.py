import re
import asyncio
from typing import List, Set, Any
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from loguru import logger
from curl_cffi import requests
import os
import sys

# Windows 代理适配
from core.utils import get_windows_proxy

class SPARouteExtractor:
    """
    三大侦查探头之 1: 现代前端单页应用 (SPA) 路由解剖刀
    提取目标站点的所有的 `main.[hash].js` 等前端资源包，用正则逆向提取出 Vue/React 的内部路由
    新增 [Phase 7] Source Map (.js.map) 和 WebAssembly (.wasm) 二进制常量提取能力
    """
    
    def __init__(self):
        # 匹配看起来像绝对路由的字符串，例如 "/act/2026_spring_fission" 或 "bonus"
        self.route_pattern = re.compile(r'["\'](\/[a-zA-Z0-9_\-\/]+)["\']')
        self.wasm_link_pattern = re.compile(r'["\']([a-zA-Z0-9_\-\.\/]+\.wasm)["\']')
        
        # 接入 Windows 系统代理
        proxy_url = get_windows_proxy()
        proxies = {"https": proxy_url, "http": proxy_url} if proxy_url else None
        
        self.session = requests.AsyncSession(impersonate="chrome120", proxies=proxies)
        
    async def extract_routes(self, target_url: str, custom_js_cfg: dict = None) -> List[str]:
        routes = [] # Now can contain strings or dicts

        logger.info(f"🔪 [SPA脱壳器] 正在解析目标: {target_url}")
        try:
            resp = await self.session.get(target_url, timeout=15)
            if resp.status_code != 200:
                logger.warning(f"[SPA脱壳器] 访问失败: HTTP {resp.status_code}")
                return list(routes)
                
            soup = BeautifulSoup(resp.text, 'html.parser')
            js_links = []
            
            # 找到所有的 script src
            for script in soup.find_all('script', src=True):
                src = script['src']
                if not src.startswith('http'):
                    src = target_url.rstrip('/') + '/' + src.lstrip('/')
                js_links.append(src)
                
            if not js_links:
                logger.info(f"[SPA脱壳器] {target_url} 未发现外部 JS 资源")
                return list(routes)
                
            # 1. 甄别目标 JS Chunk
            target_js_links = []
            if custom_js_cfg and custom_js_cfg.get("entry_js_pattern"):
                pattern = custom_js_cfg["entry_js_pattern"]
                # 转换 glob pattern 到 regex (e.g. /assets/index-*.js -> /assets/index-.*\.js)
                regex_pattern = re.compile(pattern.replace(".", "\\.").replace("*", ".*"))
                for link in js_links:
                    url_path = urlparse(link).path
                    if regex_pattern.search(url_path):
                        target_js_links.append(link)
                if not target_js_links:
                    logger.warning(f"[SPA脱壳器] 按照 {pattern} 没有匹配到构建块，回退全量分析")
                    target_js_links = js_links
            else:
                target_js_links = js_links

            logger.info(f"[SPA脱壳器] 锁定 {len(target_js_links)} 个目标 JS Chunk，开始脱壳...")
            
            all_js_text = []
            tasks = []
            for link in target_js_links:
                tasks.append(self._fetch_and_parse_js(link, all_js_text, custom_js_cfg))
                if not custom_js_cfg:
                    tasks.append(self._fetch_and_parse_js(link + ".map", None, None))


            results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results:
                if isinstance(res, list):
                    for r in res:
                        if r not in routes:
                            routes.append(r)

                    
            # 2. 第二波：从刚才所有 JS 原文中搜索可能泄漏的 WASM 地址
            wasm_links = set()
            for text in all_js_text:
                found_wasm = self.wasm_link_pattern.findall(text)
                for w in found_wasm:
                    if not w.startswith('http'):
                        w = target_url.rstrip('/') + '/' + w.lstrip('/')
                    wasm_links.add(w)
                    
            if wasm_links:
                logger.info(f"🕸️ [WASM脱壳器] 嗅探到 {len(wasm_links)} 个隐藏的 WASM 模块，尝试抽取硬编码...")
                wasm_tasks = [self._fetch_and_parse_wasm(w) for w in wasm_links]
                wasm_results = await asyncio.gather(*wasm_tasks, return_exceptions=True)
                for w_res in wasm_results:
                    if isinstance(w_res, list):
                        for wr in w_res:
                            if wr not in routes:
                                routes.append(wr)
                    
            if not custom_js_cfg:
                # 过滤出高价值路由特征 (默认全量模式下)
                valuable_routes = [r for r in routes if isinstance(r, str) and any(kw in r.lower() for kw in 
                    ['bonus', 'promo', 'free', 'beta', 'test', 'api', 'invite', 'act', 'campaign'])]
                logger.success(f"[SPA脱壳器] 成功从 {target_url} 提取到 {len(routes)} 个路径, 高价值 {len(valuable_routes)} 个")
                return valuable_routes
            else:
                # custom_js_cfg 精准模式下，查到什么返什么
                logger.success(f"[SPA脱壳器] 成功脱壳定向特征对象: {len(routes)} 个")
                return routes

            
        except Exception as e:
            logger.error(f"[SPA脱壳器] 提取异常: {e}")
            return []
            
    async def _fetch_and_parse_js(self, js_url: str, text_sink: List[str] = None, custom_js_cfg: dict = None) -> List[Any]:
        try:
            resp = await self.session.get(js_url, timeout=10)
            if resp.status_code == 200:
                if text_sink is not None:
                    text_sink.append(resp.text)
                
                results = []
                if custom_js_cfg and "extract_patterns" in custom_js_cfg:
                    for pat in custom_js_cfg["extract_patterns"]:
                        rx_str = pat.get("regex", "")
                        if rx_str.startswith("r'") or rx_str.startswith('r"'):
                            rx_str = rx_str[2:-1]  # yaml 写了 r'...' 时去掉包裹
                        try:
                            for match in re.finditer(rx_str, resp.text, re.IGNORECASE):
                                m_text = match.group(0)
                                if "enabled" in m_text.lower() or "true" in m_text.lower():
                                    # 提取 flag 名 (e.g., "free_trial_enabled": true)
                                    flag = re.search(r'["\']?([a-zA-Z0-9_-]+)["\']?\s*:', m_text)
                                    if flag:
                                        results.append({"flag": flag.group(1)})
                                else:
                                    results.append(m_text.replace('"', '').replace("'", ''))
                        except Exception as e:
                            logger.error(f"[SPA脱壳器] Regex 编译错误: {e}")
                    return results
                else:
                    found = self.route_pattern.findall(resp.text)
                    return [r for r in found if len(r) > 1 and len(r) < 50 and '{' not in r and '<' not in r]
        except Exception:
            pass
        return []

    async def _fetch_and_parse_wasm(self, wasm_url: str) -> List[str]:
        """对 WebAssembly 进行由 WABT 驱动的专业反汇编提取"""
        try:
            resp = await self.session.get(wasm_url, timeout=15)
            if resp.status_code == 200:
                content = resp.content
                from crawler.wasm_analyzer import get_wasm_analyzer
                analyzer = get_wasm_analyzer()
                return await analyzer.analyze_wasm_binary(content)
        except Exception as e:
            logger.warning(f"[WASM脱壳器] {wasm_url} 破解阻断: {e}")
        return []

    async def close(self):
        await self.session.close()

if __name__ == "__main__":
    async def test():
        extractor = SPARouteExtractor()
        routes = await extractor.extract_routes("https://siliconflow.cn")
        print("高价值路由:", routes)
        await extractor.close()
    asyncio.run(test())
