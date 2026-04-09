"""
雷达网总调度室 (Phase 9 Radar Scheduler - Global Giants Edition)

职能：
1. 动态加载 targets.yaml 中的全球大厂监控目标
2. 并发启动全维度异步守护轮询协程 (GitHub, Docker, StatusPage, SDK等)
3. 捕获回调事件并由 Fusion 引擎进行信号强度与衰减融合
4. 对高价值原始信号自动触发 Verifier 进行深度爬取与 ROI 判定
5. 实施硬核报警并向执行层看板派发资产
"""

import sys
import os
import time
import asyncio
import yaml
import random
from collections import deque
from loguru import logger

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 基础雷达模块导入
from radar.pypi_npm_watcher import run_pypi_npm_watcher_loop
from radar.github_actions_scanner import run_github_actions_scanner_loop
from radar.github_release_watcher import run_github_release_watcher_loop
from radar.status_page_poller import run_status_page_poller_loop
from radar.hn_watcher import run_hn_watcher_loop
from radar.algolia_extractor import AlgoliaExtractor
from radar.certstream_watcher import CertStreamWatcher
from radar.website_recon_prober import run_website_prober_loop
from radar.dns_ttl_watcher import run_dns_ttl_loop
from radar.docker_tag_watcher import run_docker_tag_watcher_loop
from radar.wayback_cdx import WaybackCDXExtractor
from radar.fuzzer import Tier1Fuzzer
from radar.preview_deploy_prober import PreviewDeployProber

# 核心组件导入
from core.fusion import fuse_and_decide, SignalEvent, SignalType
from core.notifier import notifier
from core.dashboard_sync import sync_to_dashboard
from core.database import get_crawler_db
from crawler.unified import CIRCUIT_BREAKER_LIMIT
from radar.url_verifier import verifier, PendingURL

# --- 1. 动态加载目标配置 ---

def load_radar_targets():
    config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "targets.yaml")
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            cfg = yaml.safe_load(f)
            t_list = []
            if 'targets' in cfg:
                t_list += cfg['targets'].get('tier_1', [])
                t_list += cfg['targets'].get('tier_2', [])
            return t_list, cfg
    except Exception as e:
        logger.error(f"❌ 目标配置文件加载失败: {e}")
        return [], {}

all_targets, full_config = load_radar_targets()
wayback_cdx_probes = full_config.get('wayback_cdx_probes', [])
js_bundle_extractor_cfg = full_config.get('js_bundle_extractor', {})
hn_launch_monitor_cfg = full_config.get('hn_launch_monitor', {})
target_domains = list(set([d for t in all_targets for d in t.get('domains', [])]))
github_orgs = list(set([t.get('github_org') for t in all_targets if t.get('github_org')]))
docker_namespaces = list(set([ns for t in all_targets for ns in t.get('docker_namespaces', [])]))

target_semantic_paths = []
for t in all_targets:
    is_billing = "Billing Probe" in t.get("name", "") or "Usage Probe" in t.get("name", "")
    sig = "billing_probe" if is_billing else "semantic_path_gen"
    for d in t.get("domains", []):
        for sp in t.get("semantic_paths", []):
            target_semantic_paths.append((d, sp, sig))

status_pages = [{"name": t.get("name"), "base_url": t.get("status_page")} for t in all_targets if t.get("status_page")]
target_sdk_repos = []
for t in all_targets:
    org = t.get('github_org')
    repos = t.get('sdk_repos', [])
    if org and repos:
        for r in repos:
            target_sdk_repos.append((org, r))

logger.success(f"🛰️ [Radar Config] 目标库扩容完成 | Domains: {len(target_domains)} | GitHub: {len(github_orgs)} | Docker: {len(docker_namespaces)} | SDK: {len(target_sdk_repos)}")

# --- 2. 状态与工具函数 ---

recent_signal_events = deque(maxlen=500)
last_signal_time = time.time()

async def run_with_backoff(name: str, coro_func, *args, **kwargs):
    """SRE 工业级统一坚韧退避引擎"""
    retry = 1
    max_d = 600
    while True:
        try:
            logger.info(f"[HA] Guarding: {name}")
            await coro_func(*args, **kwargs)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"[HA-CRASH] {name} collapsed: {e} | Restart in {retry}s")
            await asyncio.sleep(retry)
            retry = min(retry * 2, max_d)

async def dead_mans_switch_loop():
    """OSINT 系统脑死告警器 (72小时无信号判定)"""
    global last_signal_time
    while True:
        await asyncio.sleep(3600)
        silence_hours = (time.time() - last_signal_time) / 3600
        if silence_hours > 72.0:
            logger.critical(f"[HA-CRITICAL] Global Silence for {silence_hours:.1f} hours!")
            await notifier.send_alert("SYSTEM_CRITICAL", f"雷达系统已陷入 {silence_hours:.1f} 小时死寂，请检查网络或代理！")
            last_signal_time = time.time()

# --- 3. 核心发现管线 (Fusion + Verification) ---

async def centralized_radar_callback(hit_data: dict):
    """所有雷达信号的唯一归口处理中心"""
    global last_signal_time
    last_signal_time = time.time()
    source = hit_data.get("source", "unknown")
    url = hit_data.get("url")
    strength = hit_data.get("signal_strength", 0.5)

    # 1. 映射信号类型到 Fusion Enum
    sig_type = SignalType.OTHER
    source_map = {
        "pypi": SignalType.NPM_PYPI, "npm": SignalType.NPM_PYPI,
        "github_actions": SignalType.GITHUB_ACTIONS,
        "github_release": SignalType.GITHUB_RELEASE,
        "status_page": SignalType.STATUS_PAGE,
        "hackernews_show_hn": SignalType.HACKERNEWS,
        "hackernews": SignalType.HACKERNEWS,
        "algolia": SignalType.FEATURE_FLAG,
        "dns_ttl": SignalType.DNS_TTL,
        "docker": SignalType.DOCKER_TAG,
        "certstream": SignalType.CERT_STREAM,
        "wayback_cdx": SignalType.WAYBACK_CDX
    }
    for k, v in source_map.items():
        if k in source:
            sig_type = v
            break

    # 2. 构建并评估信号
    event = SignalEvent(
        source_module=source,
        signal_type=sig_type,
        signal_strength=strength,
        raw_payload=hit_data
    )
    decision = fuse_and_decide([event] + list(recent_signal_events)) # 简化的融合调用
    recent_signal_events.append(event)

    # 3. 过滤噪音
    if decision["action"] == "silent_archive" and decision.get("confidence", 0) < 0.05:
        return

    # 4. 深度验证环节 (Verifier)
    # 对所有原始信号（线索）进行自动化爬取、截图、LLM 判定 ROI，对于直接 API 等可信源自带 bypass
    if url and not hit_data.get("actionable_asset"):
        pending = PendingURL(
            url=url, 
            seed_domain=hit_data.get("org") or url, 
            trigger_signal=source,
            radar_confidence=decision["confidence"]
        )
        verified_assets = await verifier.verify_batch([pending])
        if not verified_assets:
            return
        hit_data["actionable_asset"] = verified_assets[0].model_dump()
        decision["confidence"] = verified_assets[0].roi_score / 100.0

    # 5. 最终发布逻辑 (ROI >= 70 或 强制告警)
    roi = hit_data.get("actionable_asset", {}).get("roi_score", 0) if isinstance(hit_data.get("actionable_asset"), dict) else 0

    # 防护：express_lane 必须携带合法 URL + 真实 ROI 才能发报，否则只是监控信号，不推送
    if not url or url == "N/A":
        if decision["action"] == "express_lane":
            logger.info(f"[Orchestrator] express_lane 信号 ({source}) 无有效 URL，升级为监控日志，不推送终端")
        return

    if roi >= 70 or (decision["action"] == "express_lane" and decision["confidence"] > 0.6 and roi > 0):
        logger.success(f"🎯 [Orchestrator] High Value Confirmed: {url} (ROI: {roi})")
        title = hit_data.get("title") or f"[{source.upper()}] New Signal"
        msg = hit_data.get("message") or f"Detected interesting activity for {hit_data.get('org', 'Target')}"
        await notifier.send_arbitrage_alert(
            target_url=url,
            roi_score=max(roi, int(decision["confidence"]*100)),
            value=hit_data.get("actionable_asset", {}).get("estimated_value", 0),
            reason=msg,
            is_express=(roi >= 90)
        )
        await sync_to_dashboard(hit_data)

# --- 4. CertStream 回调包装桥接层 ---
async def run_certstream_watcher_loop(callback):
    """将 WebSocket 类回调桥接到集中信号队列的胶水协程"""
    watcher = CertStreamWatcher(seed_domains=target_domains)
    if not hasattr(watcher, 'add_callback'):
        logger.error("[CertStream] CertStreamWatcher 不支持 add_callback，请检查接口")
        from core.notifier import notifier
        await notifier.send_alert("SYSTEM_CRITICAL", "CertStreamWatcher 接口契约破裂 (缺少 add_callback)，证书监听矩阵已结构性宕机！")
        return
        
    async def _cert_cb(domain):
        event_dict = {
            "source": "certstream",
            "url": f"https://{domain}",
            "org": domain,
            "signal_strength": 0.9, 
            "title": f"New Subdomain Cert: {domain}"
        }
        try:
            await callback(event_dict)
        except Exception as e:
            logger.error(f"[ERR] [CertStream] Bridge collapsed: {e}")
            
    watcher.add_callback(_cert_cb)
    await watcher.start_watching()

# --- 5. 周期性全量扫描 (Deep Dive) ---

async def run_deep_scan_daily():
    """每日对核心大厂资产进行深度渗透挖掘"""
    from radar.spa_route_extractor import SPARouteExtractor
    from radar.semantic_path_generator import SemanticPathGenerator
    spa_ext = SPARouteExtractor()
    sem_gen = SemanticPathGenerator()
    cdx_ext = WaybackCDXExtractor()
    
    while True:
        # A. 执行精确制导的 CDX 探针挖掘 (替代耗时的全量泛扫)
        if wayback_cdx_probes:
            logger.info(f"🕰️ [Deep Scan] Starting Wayback CDX probes ({len(wayback_cdx_probes)} targets)")
            for probe in wayback_cdx_probes:
                query = probe.get("cdx_query")
                name = probe.get("name", "Unknown CDX Probe")
                if query:
                    patterns = await cdx_ext.extract_from_query(query, name)
                    for p in patterns:
                        await centralized_radar_callback({
                            "source": "wayback_cdx", 
                            "org": name, 
                            "url": p["url"], 
                            "signal_strength": 0.85  # 精准挖矿，权重提升
                        })
                        
        # B. 常规全量域名深层探测
        scan_list = target_domains[:]
        random.shuffle(scan_list)
        logger.info(f"🌊 [Deep Scan] Starting daily deep dive session for {len(scan_list)} domains")
        
        for domain in scan_list:
            try:
                # 前置熔断检查：如果域名已熔断，跳过高消耗的 Wayback/SPA/LLM，直接进 Fuzzer
                try:
                    _db = get_crawler_db()
                    _cb_tripped = _db.get_site_failure_count(domain) >= CIRCUIT_BREAKER_LIMIT
                except Exception:
                    _cb_tripped = False

                if _cb_tripped:
                    logger.debug(f"[Deep Scan] {domain} 处于熔断期，跳过 Wayback/SPA/LLM，仅道 Fuzzer")
                else:
                    # 1. 静态高价值路径直探 (semantic_paths & billing_probes)
                    for d, sp, sig in target_semantic_paths:
                        if d == domain:
                            url = f"https://{d}{sp}" if sp.startswith("/") else f"https://{d}/{sp}"
                            # 发送强信号给 Verifier
                            await centralized_radar_callback({"source": sig, "org": domain, "url": url, "signal_strength": 0.9 if sig == "billing_probe" else 0.8})

                    # 2. Wayback 历史沉淀 (现在被抽取到专向循环里，跳过通配符泛查)
                    
                    # 3. SPA/WASM 脱壳
                    custom_js_cfg = None
                    if js_bundle_extractor_cfg and "targets" in js_bundle_extractor_cfg:
                        for t in js_bundle_extractor_cfg["targets"]:
                            if t.get("domain") == domain:
                                custom_js_cfg = t
                                break
                    
                    routes = await spa_ext.extract_routes(f"https://{domain}", custom_js_cfg)
                    for r in routes: 
                        if isinstance(r, dict):  # Feature Flag 特殊字典
                            sig = "feature_flag"
                            flag_name = r['flag']
                            if "admin" in flag_name.lower():
                                logger.warning(f"[Honeypot] 检测到诱饵 Flag: {flag_name}，已静默抛弃")
                                continue # 丢弃 admin 蜜罐
                                
                            url = f"https://{domain}/__feature_flag/{flag_name}"
                            strength = 0.9 if 'enabled' in flag_name and any(k in flag_name for k in ['credit', 'free']) else 0.7
                            await centralized_radar_callback({"source": sig, "org": domain, "url": url, "signal_strength": strength, "message": f"Found flag: {flag_name}"})
                        else:
                            await centralized_radar_callback({"source": "spa_extractor", "org": domain, "url": r, "signal_strength": 0.6})
                    
                    # 3. LLM 语义推测
                    candidates = await sem_gen.generate_candidates(domain)
                    for c in candidates: await centralized_radar_callback({"source": "semantic_path_gen", "org": domain, "url": f"https://{domain}{c}", "signal_strength": 0.4})

                # 4. Fuzzer 探活（任何情况下都跑）
                hits = await Tier1Fuzzer(domain).run_scan()
                for h in hits: await centralized_radar_callback({"source": "tier1_fuzzer", "org": domain, "url": h["url"], "signal_strength": h.get("confidence", 0.5)})
                
            except Exception as e:
                logger.warning(f"⚠️ [Deep Scan] Failed for {domain}: {e}")
            await asyncio.sleep(30) # 频率保护
            
        await asyncio.sleep(86400) # 24h 周期

# --- 6. 主入口 ---

async def main():
    logger.info("=========================================")
    logger.info("[MAIN] Data Discovery Radar Core - RUNNING")
    logger.info("=========================================")
    
    tasks = [
        # 基准轮询类
        asyncio.create_task(run_with_backoff("PyPI/NPM", run_pypi_npm_watcher_loop, centralized_radar_callback)),
        asyncio.create_task(run_with_backoff("HackerNews", run_hn_watcher_loop, centralized_radar_callback)),
        
        # 配置驱动的动态扫描类
        asyncio.create_task(run_with_backoff("GitHubActions", run_github_actions_scanner_loop, centralized_radar_callback, org_list=github_orgs)),
        asyncio.create_task(run_with_backoff("GitHubRelease", run_github_release_watcher_loop, centralized_radar_callback, repo_list=target_sdk_repos)),
        asyncio.create_task(run_with_backoff("StatusPage", run_status_page_poller_loop, centralized_radar_callback, url_list=status_pages)),
        asyncio.create_task(run_with_backoff("DockerTag", run_docker_tag_watcher_loop, centralized_radar_callback, docker_namespaces)),
        asyncio.create_task(run_with_backoff("DnsTtl", run_dns_ttl_loop, centralized_radar_callback, target_domains)),
        asyncio.create_task(run_with_backoff("WebsiteRecon", run_website_prober_loop, centralized_radar_callback)),
        
        # 全量流式源与深挖类
        asyncio.create_task(run_with_backoff("CertStream", run_certstream_watcher_loop, centralized_radar_callback)),
        asyncio.create_task(run_with_backoff("DeepScanDaily", run_deep_scan_daily)),
        asyncio.create_task(dead_mans_switch_loop()),
    ]
    
    try:
        await asyncio.gather(*tasks)
    except KeyboardInterrupt:
        logger.info("🛑 雷达网主控台手动停机...")
    except Exception as e:
        logger.exception(f"🔥 [FATAL] Scheduler collapsed: {e}")

if __name__ == "__main__":
    asyncio.run(main())
