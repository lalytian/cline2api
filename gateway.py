#!/usr/bin/env python3
"""
cline2api - 本地轻量 Cline 管理网关 (coibox OCI ARM 宿主机版)
1. 原生 Web 管理面板 (/admin)，支持：开关、删除、重登录、设备码一键发起 OAuth、手动粘贴导入 RefreshToken
2. 免费模型实时监控面板 (/admin/models) 与探活测试（与 Cline 客户端官方目录完全对齐）
3. 将 Cline 官方客户端协议本地拼接，提供 OpenAI 兼容端点 (/v1/models, /v1/chat/completions)
4. 自动剥离 max_tokens，非流式请求自动强制转 SSE 拼装防 500
5. 账号池轮询 (Round-Robin) 与 429 自动读取冷却时间退避切号
"""

import asyncio
import json
import logging
import os
import re
import sys
import time
import uuid
from typing import Dict, List, Optional, Any

import httpx
import uvicorn
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware

DATA_DIR = os.environ.get("CLINE2API_DATA_DIR", os.path.dirname(os.path.abspath(__file__)))
ACCOUNTS_FILE = os.path.join(DATA_DIR, "accounts.json")
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")

CLINE_API_BASE = "https://api.cline.bot/api/v1"
WORKOS_DEVICE_URL = "https://api.workos.com/user_management/authorize/device"
WORKOS_AUTH_URL = "https://api.workos.com/user_management/authenticate"
WORKOS_CLIENT_ID = "client_01K3A541FN8TA3EPPHTD2325AR"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cline2api")

app = FastAPI(title="Cline2API Gateway", docs_url=None, redoc_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pending_oauth: Dict[str, Dict[str, Any]] = {}
current_account_idx = 0
lock = asyncio.Lock()

# ----------------- 数据持久化 -----------------

def load_config() -> Dict[str, Any]:
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"api_key": os.environ.get("API_KEY", "sk-cline-default-key"), "admin_password": os.environ.get("ADMIN_PASSWORD", "admin123")}

def save_config(cfg: Dict[str, Any]):
    tmp = CONFIG_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    os.replace(tmp, CONFIG_FILE)

def load_accounts() -> List[Dict[str, Any]]:
    if os.path.exists(ACCOUNTS_FILE):
        try:
            with open(ACCOUNTS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return []

def save_accounts(accs: List[Dict[str, Any]]):
    tmp = ACCOUNTS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(accs, f, indent=2, ensure_ascii=False)
    os.replace(tmp, ACCOUNTS_FILE)

# ----------------- Token 刷新与调度 -----------------

WORKOS_CLIENT_ID = "client_01K3A541FN8TA3EPPHTD2325AR"
WORKOS_AUTH_URL = "https://api.workos.com/user_management/authenticate"

async def refresh_via_workos_fallback(refresh_token: str) -> Optional[Dict[str, str]]:
    """双通道自愈：直接调用 WorkOS 认证底座刷新 (对齐 luawei1 refreshViaWorkOS)"""
    payload = {
        "grant_type": "refresh_token",
        "client_id": WORKOS_CLIENT_ID,
        "refresh_token": refresh_token
    }
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(WORKOS_AUTH_URL, json=payload, headers={"Content-Type": "application/json"})
            if resp.status_code == 200:
                data = resp.json()
                at = data.get("access_token")
                rt = data.get("refresh_token")
                if at:
                    logger.info("Token successfully self-healed via WorkOS fallback channel!")
                    return {"access_token": at, "refresh_token": rt or refresh_token}
            else:
                logger.warning(f"WorkOS fallback rejected: HTTP {resp.status_code} {resp.text[:120]}")
    except Exception as e:
        logger.error(f"WorkOS fallback exception: {e}")
    return None

async def refresh_account_token(acc: Dict[str, Any]) -> Optional[str]:
    url = f"{CLINE_API_BASE}/auth/refresh"
    payload = {
        "refreshToken": acc["refreshToken"],
        "grantType": "refresh_token"
    }
    new_at = None
    new_rt = None

    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            res = await client.post(url, json=payload, headers={"Content-Type": "application/json"})
            if res.status_code == 200:
                data = res.json().get("data", {})
                new_at = data.get("accessToken")
                new_rt = data.get("refreshToken")
            elif res.status_code in [400, 401, 403]:
                logger.warning(f"Cline /auth/refresh returned {res.status_code}, triggering WorkOS dual-channel self-heal...")
                healed = await refresh_via_workos_fallback(acc["refreshToken"])
                if healed:
                    new_at = healed["access_token"]
                    new_rt = healed["refresh_token"]
                else:
                    acc["last_error"] = f"HTTP {res.status_code}: {res.text[:120]}"
            else:
                acc["last_error"] = f"HTTP {res.status_code}: {res.text[:120]}"
        except Exception as e:
            logger.warning(f"Cline refresh network error, attempting WorkOS fallback: {e}")
            healed = await refresh_via_workos_fallback(acc["refreshToken"])
            if healed:
                new_at = healed["access_token"]
                new_rt = healed["refresh_token"]
            else:
                acc["last_error"] = str(e)

    if new_at:
        acc["accessToken"] = new_at
        acc["expiry"] = int(time.time()) + 3000
        if new_rt:
            acc["refreshToken"] = new_rt
        acc["status"] = "active"
        acc["last_error"] = ""
        accs = load_accounts()
        for i, item in enumerate(accs):
            if item.get("id") == acc.get("id") or item.get("email") == acc.get("email"):
                accs[i] = acc
                break
        save_accounts(accs)
        return new_at
    return None

async def get_valid_token(acc: Dict[str, Any]) -> Optional[str]:
    now = int(time.time())
    if acc.get("accessToken") and acc.get("expiry", 0) > now + 60:
        return acc["accessToken"]
    return await refresh_account_token(acc)

async def pick_available_account() -> Optional[Dict[str, Any]]:
    global current_account_idx
    async with lock:
        accs = load_accounts()
        enabled_accs = [a for a in accs if a.get("enabled", True)]
        if not enabled_accs:
            return None
        
        now = int(time.time())
        for _ in range(len(enabled_accs)):
            current_account_idx = (current_account_idx + 1) % len(enabled_accs)
            candidate = enabled_accs[current_account_idx]
            if candidate.get("cooldownUntil", 0) <= now:
                return candidate
        
        enabled_accs.sort(key=lambda x: x.get("cooldownUntil", 0))
        return enabled_accs[0]

def parse_cooldown_ms(body: str, status: int) -> int:
    m = re.search(r"try again in (?:(\d+)h\s*)?(?:(\d+)m\s*)?(?:(\d+)s)?", body, re.IGNORECASE)
    if m:
        h = int(m.group(1) or 0)
        minutes = int(m.group(2) or 0)
        s = int(m.group(3) or 0)
        total_s = h * 3600 + minutes * 60 + s
        if total_s > 0:
            return total_s * 1000
    if status == 429:
        return 60 * 1000
    return 30 * 1000

def build_cline_headers(access_token: str, session_id: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer workos:{access_token}",
        "Content-Type": "application/json",
        "User-Agent": "Cline/3.0.65",
        "HTTP-Referer": "https://cline.bot",
        "X-Title": "Cline",
        "X-IS-MULTIROOT": "false",
        "X-CLIENT-TYPE": "cline-cli",
        "X-CLIENT-VERSION": "3.0.65",
        "X-PLATFORM": "terminal",
        "X-PLATFORM-VERSION": "3.0.65",
        "X-CORE-VERSION": "0.0.86",
        "X-Task-ID": session_id,
    }

# ----------------- 官方客户端完全对齐的免费模型定义 -----------------

OFFICIAL_FREE_MODELS = [
    {
        "id": "cline-free/deepseek-v4.1-flash",
        "name": "DeepSeek V4.1 Flash (free)",
        "description": "Fast and efficient with 1M context window",
        "badge": "FREE",
        "source": "official_free",
        "type": "官方免配额通道"
    },
    {
        "id": "cline-free/gemini-3.8-flash",
        "name": "Gemini 3.8 Flash (free)",
        "description": "Google most intelligent Flash model",
        "badge": "FREE",
        "source": "official_free",
        "type": "官方免配额通道"
    },
    {
        "id": "cline-free/mimo-v2.6-flash",
        "name": "MiMo-V2.6-Flash (free)",
        "description": "Mixture-of-Experts architecture with 309B total parameters",
        "badge": "FREE",
        "source": "official_free",
        "type": "官方免配额通道"
    },
    {
        "id": "cline-free/muse-spark-1.3-contributor",
        "name": "Muse Spark 1.3 Contributor (free)",
        "description": "Meta multimodal reasoning model for experimentation, learning, and early-stage agentic, multi-agent, and coding workflows.",
        "badge": "FREE",
        "source": "official_free",
        "type": "官方免配额通道"
    }
]

# 官方免费通道模型名映射（下发别名 -> 上游真实模型名）
FREE_MODEL_UPSTREAM_MAP = {
    "cline-free/deepseek-v4.1-flash": "deepseek/deepseek-v4.1-flash",
    "cline-free/gemini-3.8-flash": "google/gemini-3.8-flash",
    "cline-free/mimo-v2.6-flash": "xiaomi/mimo-v2.6-flash",
    "cline-free/muse-spark-1.3-contributor": "meta/muse-spark-1.3-contributor",
    "cline-free/nemotron-3.5-super-vl": "nvidia/nemotron-3.5-super-vl",
    "cline-free/solar-mini4": "upstage/solar-mini4",
    "cline-free/auto": "xiaomi/mimo-v2.6-flash",
}

# recommended-models 动态免费模型缓存（10分钟TTL）
recommended_free_cache: List[Dict[str, Any]] = []
recommended_free_last_fetch = 0.0

async def fetch_recommended_free_models(client: httpx.AsyncClient, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    global recommended_free_cache, recommended_free_last_fetch
    now = time.time()
    if recommended_free_cache and (now - recommended_free_last_fetch < 600):
        return recommended_free_cache
    try:
        r = await client.get(f"{CLINE_API_BASE}/ai/cline/recommended-models", headers=headers, timeout=5.0)
        if r.status_code == 200:
            free_list = r.json().get("free", [])
            cached = []
            for item in free_list:
                mid = item.get("id")
                if not mid:
                    continue
                cached.append({
                    "id": mid,
                    "name": item.get("name", mid),
                    "description": item.get("description", ""),
                    "badge": "FREE",
                    "source": "official_recommended_free",
                    "type": "官方实时免配额通道"
                })
            if cached:
                recommended_free_cache = cached
                recommended_free_last_fetch = now
                logger.info(f"动态同步到官方 recommended-models: {len(cached)} 个免费模型")
                return cached
    except Exception as e:
        logger.warning(f"获取 recommended-models 异常，回退内置: {e}")
    return recommended_free_cache or OFFICIAL_FREE_MODELS

def resolve_upstream_model(model_name: str) -> str:
    if not model_name:
        return model_name
    m = model_name.strip()
    # 命中显式映射
    if m in FREE_MODEL_UPSTREAM_MAP:
        return FREE_MODEL_UPSTREAM_MAP[m]
    # 处理 cline/ 前缀 (CPA 侧下发)
    if m.startswith("cline/"):
        bare = m[6:]
        cf = f"cline-free/{bare}"
        if cf in FREE_MODEL_UPSTREAM_MAP:
            return FREE_MODEL_UPSTREAM_MAP[cf]
        # 常见官方前缀补全
        if "/" not in bare:
            if "deepseek" in bare:
                return f"deepseek/{bare}"
            if "gemini" in bare:
                return f"google/{bare}"
            if "mimo" in bare:
                return f"xiaomi/{bare}"
            if "muse" in bare:
                return f"meta/{bare}"
    return m


# ----------------- 网关数据面路由 -----------------

@app.get("/healthz")
async def healthz():
    accs = load_accounts()
    active = sum(1 for a in accs if a.get("enabled", True) and a.get("cooldownUntil", 0) <= time.time())
    return {"status": "ok", "total_accounts": len(accs), "active_accounts": active}

@app.get("/v1/models")
async def list_models(request: Request):
    acc = await pick_available_account()
    if not acc:
        return JSONResponse({"data": []})
    token = await get_valid_token(acc)
    if not token:
        return JSONResponse({"data": []})

    headers = build_cline_headers(token, f"task_{int(time.time())}")
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            r = await client.get(f"{CLINE_API_BASE}/models", headers=headers)
            models_data = r.json().get("data", []) if r.status_code == 200 else []
            existing_ids = {m.get("id") for m in models_data}
            
            # 动态融合 recommended-models 官方免费通道模型
            rec_free = await fetch_recommended_free_models(client, headers)
            for fm in rec_free:
                if fm["id"] not in existing_ids:
                    models_data.append({
                        "id": fm["id"],
                        "object": "model",
                        "created": int(time.time()),
                        "owned_by": "cline-free"
                    })
                    existing_ids.add(fm["id"])
                    
            return JSONResponse({"object": "list", "data": models_data})
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    cfg = load_config()
    auth_header = request.headers.get("Authorization", "")
    token_part = auth_header[7:].strip() if auth_header.startswith("Bearer ") else auth_header.strip()
    expected = (cfg.get("api_key") or "").strip()
    if expected and token_part != expected:
        logger.warning(f"Auth mismatch: received [{token_part[:10]}...] received_len={len(token_part)} received_repr={repr(token_part)} expected_repr={repr(expected)}")
        raise HTTPException(status_code=401, detail="Invalid API Key")

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    # 核心安全补丁 1: 剥离 max_tokens, 避免触发上游针对探活的 500/429 惩罚限流
    body.pop("max_tokens", None)
    body.pop("max_completion_tokens", None)

    # 核心安全补丁 2: 清洗与还原超长/畸形 Tools (对齐 luawei1 针对 Codex 桌面端 Meta 400 修复)
    if "tools" in body and isinstance(body["tools"], list):
        cleaned_tools = []
        for t in body["tools"]:
            if isinstance(t, dict) and t.get("type") == "function":
                fn = t.get("function", {})
                if isinstance(fn, dict):
                    # 修复空参数或类型错误
                    params = fn.get("parameters")
                    if not params or not isinstance(params, dict) or params.get("type") is None:
                        fn["parameters"] = {"type": "object", "properties": {}}
                    # 截短超长函数名 (防上游 400)
                    fname = fn.get("name", "")
                    if len(fname) > 64:
                        fn["name"] = fname[:64]
                cleaned_tools.append(t)
            else:
                cleaned_tools.append(t)
        body["tools"] = cleaned_tools

    orig_model = body.get("model", "")
    target_model = resolve_upstream_model(orig_model)
    body["model"] = target_model
    is_client_stream = body.get("stream", False)
    session_id = f"task_{uuid.uuid4().hex[:12]}"

    for attempt in range(3):
        acc = await pick_available_account()
        if not acc:
            return JSONResponse({"error": {"message": "All accounts are cooling or disabled", "type": "server_error"}}, status_code=503)

        token = await get_valid_token(acc)
        if not token:
            continue

        headers = build_cline_headers(token, session_id)
        upstream_url = f"{CLINE_API_BASE}/chat/completions"

        if is_client_stream:
            # 核心强化: 首字 20s 断流看门狗 (超时即判定上游假死，快速换号重试)
            client = httpx.AsyncClient(timeout=httpx.Timeout(120.0, connect=15.0, read=20.0))
            req_stream = client.build_request("POST", upstream_url, json=body, headers=headers)
            try:
                r = await client.send(req_stream, stream=True)
                if r.status_code == 200:
                    async def stream_generator():
                        try:
                            async for chunk in r.aiter_raw():
                                yield chunk
                        finally:
                            await r.aclose()
                            await client.aclose()
                    return StreamingResponse(stream_generator(), media_type="text/event-stream")
                else:
                    err_bytes = await r.aread()
                    await r.aclose()
                    await client.aclose()
                    err_text = err_bytes.decode(errors="ignore")
                    if r.status_code == 429 or "Daily free limit reached" in err_text or "insufficient_credits" in err_text or r.status_code == 402:
                        cd_ms = parse_cooldown_ms(err_text, r.status_code) if (r.status_code == 429 or "Daily" in err_text) else 86400000
                        acc["cooldownUntil"] = int(time.time()) + int(cd_ms / 1000)
                        accs = load_accounts()
                        for i, a in enumerate(accs):
                            if a.get("id") == acc.get("id"):
                                accs[i] = acc
                        save_accounts(accs)
                        continue
                    return JSONResponse({"error": {"message": f"Upstream error: {err_text[:300]}"}}, status_code=r.status_code)
            except Exception:
                await client.aclose()
                continue
        else:
            stream_body = dict(body)
            stream_body["stream"] = True
            # 核心强化: 非流式首字 20s 断流看门狗
            client = httpx.AsyncClient(timeout=httpx.Timeout(120.0, connect=15.0, read=20.0))
            try:
                r = await client.post(upstream_url, json=stream_body, headers=headers)
                if r.status_code != 200:
                    err_text = r.text
                    if r.status_code == 429 or "Daily free limit reached" in err_text or "insufficient_credits" in err_text or r.status_code == 402:
                        cd_ms = parse_cooldown_ms(err_text, r.status_code) if (r.status_code == 429 or "Daily" in err_text) else 86400000
                        acc["cooldownUntil"] = int(time.time()) + int(cd_ms / 1000)
                        accs = load_accounts()
                        for i, a in enumerate(accs):
                            if a.get("id") == acc.get("id"):
                                accs[i] = acc
                        save_accounts(accs)
                        await client.aclose()
                        continue
                    await client.aclose()
                    return JSONResponse({"error": {"message": err_text[:300]}}, status_code=r.status_code)

                full_content = ""
                full_reasoning = ""
                model_name = body.get("model", "")
                for line in r.text.splitlines():
                    if line.startswith("data: ") and line.strip() != "data: [DONE]":
                        try:
                            chunk = json.loads(line[6:])
                            delta = chunk.get("choices", [{}])[0].get("delta", {})
                            full_content += delta.get("content", "")
                            full_reasoning += delta.get("reasoning", "")
                        except Exception:
                            pass
                
                if not full_content and full_reasoning:
                    full_content = full_reasoning

                # 优化点2：防空响应与假成功探测（若内容全空或上游隐匿报错，标记冷却并换号重试）
                if not full_content.strip() or "empty response content" in r.text:
                    logger.warning(f"[{acc.get('email')}] 上游返回空内容或 empty response content，标记冷却 60s 并切号重试")
                    acc["cooldownUntil"] = int(time.time()) + 60
                    accs = load_accounts()
                    for i, a in enumerate(accs):
                        if a.get("id") == acc.get("id"):
                            accs[i] = acc
                    save_accounts(accs)
                    await client.aclose()
                    continue

                await client.aclose()
                return JSONResponse({
                    "id": f"chatcmpl-{uuid.uuid4().hex}",
                    "object": "chat.completion",
                    "created": int(time.time()),
                    "model": model_name,
                    "choices": [{
                        "index": 0,
                        "message": {"role": "assistant", "content": full_content},
                        "finish_reason": "stop"
                    }],
                    "usage": {"prompt_tokens": 10, "completion_tokens": len(full_content), "total_tokens": 10 + len(full_content)}
                })
            except Exception:
                await client.aclose()
                continue

    return JSONResponse({"error": {"message": "Failed to complete request across accounts"}}, status_code=502)

# ----------------- 免费模型监控 API -----------------

@app.get("/admin/api/free-models")
async def admin_get_free_models():
    """获取所有免费模型及其健康状态"""
    acc = await pick_available_account()
    if not acc:
        return {"status": "error", "message": "暂无可用账号，请先添加账号", "models": []}
    
    token = await get_valid_token(acc)
    if not token:
        return {"status": "error", "message": "获取凭证失败", "models": []}

    headers = build_cline_headers(token, "free-models-probe")
    async with httpx.AsyncClient(timeout=10.0) as client:
        # 1. 加载官方免费核心模型（包含客户端顶部的 DeepSeek V4.1、Kimi K3、Muse Spark、GLM 5.3 Flash 等）
        free_models = list(OFFICIAL_FREE_MODELS)
        existing_ids = {fm["id"] for fm in free_models}

        # 2. 获取全量模型列表中带 :free / -free 的开源免费模型
        r_all = await client.get(f"{CLINE_API_BASE}/models", headers=headers)
        if r_all.status_code == 200:
            all_data = r_all.json().get("data", [])
            for m in all_data:
                mid = m.get("id", "")
                if (":free" in mid.lower() or "-free" in mid.lower()) and mid not in existing_ids:
                    name_part = mid.split("/")[-1].replace(":free", "")
                    clean_name = f"{name_part.replace('-', ' ').title()} (free)"
                    free_models.append({
                        "id": mid,
                        "name": clean_name,
                        "description": f"由 {m.get('owned_by', '社区')} 提供的开源免费通道",
                        "badge": "FREE",
                        "source": "community_free",
                        "type": "开源免费通道"
                    })
                    existing_ids.add(mid)

        return {"status": "success", "models": free_models}

@app.post("/admin/api/free-models/test")
async def admin_test_free_model(req: Request):
    """在线探活单个模型"""
    data = await req.json()
    model_id = data.get("model")
    if not model_id:
        return {"status": "error", "message": "模型名不能为空"}

    acc = await pick_available_account()
    if not acc:
        return {"status": "error", "message": "暂无可用账号"}
    token = await get_valid_token(acc)
    if not token:
        return {"status": "error", "message": "获取 Token 失败"}

    headers = build_cline_headers(token, f"test_{int(time.time())}")
    start_time = time.time()
    async with httpx.AsyncClient(timeout=20.0) as client:
        try:
            r = await client.post(
                f"{CLINE_API_BASE}/chat/completions",
                headers=headers,
                json={
                    "model": model_id,
                    "messages": [{"role": "user", "content": "hi"}],
                    "stream": False
                }
            )
            cost_ms = int((time.time() - start_time) * 1000)
            if r.status_code == 200:
                res_data = r.json().get("data", {})
                content = res_data.get("choices", [{}])[0].get("message", {}).get("content", "")
                return {
                    "status": "success",
                    "http_code": 200,
                    "latency_ms": cost_ms,
                    "reply": content[:80] or "(OK)"
                }
            else:
                return {
                    "status": "fail",
                    "http_code": r.status_code,
                    "latency_ms": cost_ms,
                    "error": r.text[:200]
                }
        except Exception as e:
            return {"status": "fail", "error": str(e)}

# ----------------- 管理后台单页 HTML -----------------

ADMIN_HTML = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>Cline2API - 控制台与模型监控</title>
    <link rel="icon" type="image/png" href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAgAAAAIACAYAAAD0eNT6AAAqsUlEQVR4nO3deXRV5bnH8d8JCWKYEWqCQhRkkJRREa0CipVVawDvhbbeJVRsa+3gqsUWa/XWVuvQYkdXK1ZdXSAXW6eLDMK9Lg0UW7iWUSYhTEEhMpSEMEQhJ+z7R20kkpDpnP28e7/fz1rvrat3FR/Ofvfz/M67T04SAhBlgfG/P2H87wfQRNy8gFusB3q60XMAR3AzAuGK+4BvLnoSEBJuNiA9GPSpRa8CUoybCmgeBr0tehjQRNw8QMMx7KOBvgY0ADcKUDcGfjzQ54BacGMAH2Pg+4G+B4gbAX5j4EOiD8JTbHz4hIGPhqAvwgtsdMQdQx/NQY9EbLG5ETcMfKQTPROxwWZGHDD0YYH+iUhjAyOqGPpwCb0UkcOmRZQw9BEF9FVEAhsVrmPoI8rosXAWmxOuYvAjTui1cA6bEi5h6MMH9F04gY0IFzD44SP6L0yxAWGFoQ98jF6M0LHpEDYGP1A3ejJCw2ZDGBj6QOPRn5FWbDCkE4MfaD76NNKCjYV0YPADqUe/RkqxoZBKDH4g/ejbSAk2ElKBwQ+Ej/6NZmEDoTkY/IA9+jiahI2DpmDwA+6hn6NR2DBoDAY/4D76OhqEjYKGYPAD0UN/xxmxQXAmDH4g+ujzqBUbA7Vh8APxQ79HDWwInIrBD8QffR+SpAzrAuAMhj/gB+51SCIJgmYA+IwZ4DEuvr8Y/AD+hVngIS66fxj8AOrCTPAInwHwC8MfwJnQIzxC2vMDNzWAxmI+xBwnAPHH8AfQFPSOmCPhxRc3L4BUYVbEEBc1fhj8ANKFmREjPAKIF4Y/gHSix8QIaS4euCkBhI35EXGcAEQfwx+ABXpPxJHgooubD4ArmCURxAlANDH8AbiEnhRBBIDo4UYD4CJ6U8RwbBMd3FwAooLZEgGcAEQDwx9AlNCzIoAA4D5uJABRRO9yHMc07uLmARAXzBoHcQLgJoY/gDihpzmIAOAebhQAcURvcwzHMu7g5gDgC2aPAzgBcAPDH4BP6HkOIADY40YA4CN6nzECgC1uAAA+owca4jmMDTY9ANTEPAoZJwDhY/gDwOnojSEjAISLDQ4AdaNHhogAEB42NgDUj14ZEgJAONjQANBw9MwQ8KGL9GITA0DzMKfShBOA9GH4A0Dz0UvThACQHmxYAEgdemoaEABSj40KAKlHb00xAkBqsUEBIH3osSlEAEgdNiYApB+9NkUIAKnBhgSA8NBzU4AA0HxsRAAIH723mQgAzcMGBAA79OBmIAA0HRsPAOzRi5uIANA0bDgAcAc9uQkIAI3HRgMA99CbG4kA0DhsMABwFz26EQgADcfGAgD30asbiADQMGwoAIgOenYDEADqx0YCgOihd9eDAHBmbCAAiC56+BkQAOrGxgGA6KOX14EAUDs2DADEBz29FgSA07FRACB+6O2fQACoiQ0CAPFFjz8FAeBjbAwAiD96/UcIAP/EhgAAf9DzRQCQ2AgA4CPve7/vAcD7DQAAHvN6BvgeAAAA8JLPAcDr5AcAkOTxLPA1AHh7wQEAp/FyJvgYALy80ACAM/JuNvgWALy7wACABvNqRvgUALy6sACAJvFmVvgUAAAAwEd8CQDeJDoAQLN5MTN8CABeXEgAQErFfnbEPQDE/gICANIm1jMkzgEg1hcOABCK2M6SOAcAAABQh7gGgNgmNgBA6GI5U+IYAGJ5oQAApmI3W+IWAGJ3gQAAzojVjIlbAAAAAA0QpwAQq2QGAHBSbGZNXAJAbC4IAMB5sZg5cQgAsbgQAIBIifzsiUMAAAAAjRT1ABD5BAYAiKxIz6AoB4BIv/AAgFiI7CyKagCI7AsOAIidSM6kqAYAAADQDFEMAJFMWgCAWIvcbIpaAIjcCwwA8EakZlTUAgAAAEiBKAWASCUrAICXIjOrohIAIvOCAgC8F4mZFZUAAAAAUigKASASSQoAgFM4P7uiEAAAAECKuR4AnE9QAADUwekZ5nIAcPqFAwCgAZydZS4HAAAAkCauBgBnExMAAI3k5ExzMQA4+UIBANAMzs02FwMAAABIM9cCgHMJCQCAFHFqxrkWAAAAQAhcCgBOJSMAANLAmVnnUgAAAAAhcSUAOJOIAABIMydmngsBwIkXAgCAEJnPPhcCAAAACJl1ADBPQAAAGDGdgdYBAAAAGEgY/rt59w84qFOnTsrJyamxOnfurHbt2tW6WrVqpczMTGVlZSkrK6v6nzMzMyVJyWRSVVVVSiaTSiaTqqio0LFjx6rX0aNHVVpaqoMHD6q0tFSlpaXat2+fSkpKVFJSovfff18VFRXGrwqQViazmAAAeKZz587q0aOHevbsqR49elT/84UXXqicnBy1bNnSusTTlJWVaefOndq5c6d27NihHTt2qKioSO+8847ef/996/KA5vIqADD8gTTLzs5Wv379NGDAAA0YMED9+/fXgAED1LlzZ+vSUurQoUN65513tHHjRq1Zs0arV6/WunXrODVA1IQ+jwkAQAwkEgn17dtXV1xxRfW6+OKLlZHh58d8qqqqtGXLFr311ltatmyZli9frk2bNikIaD1wlhcBgDsQaKZEIqEhQ4Zo9OjRGj58uC6//HJ17NjRuiynHTp0SMuWLVNhYaEKCwu1du1aAgFcE+pMJgAAEXH++edr9OjRGj16tK699trYHeWHrbS0VIsXL9aiRYu0cOFCPksAF8Q6ADD8gUa4+OKLNX78eI0fP16DBg2yLifW1qxZo4ULF2ru3LlasWKFdTnwV2hzmQAAOGbgwIGaMGGCxo8fr4svvti6HC+9++67mjNnjl5++WX97W9/08mTJ61Lgj9iGQAY/kAdOnfurIkTJ+rWW2/VgAEDrMvBKUpKSvSnP/1Js2fP1po1a6zLgR9Cmc0EAMBIixYt9LnPfU5f+cpXNGbMGGVlZVmXhHps2rRJs2bN0syZM/nMANIpVgGA4Q98pEOHDrrtttt0xx13qHv37tbloAmSyaQWLlyoZ555RgsXLlRVVZV1SYiftM9nAgAQkl69eunOO+/U5MmT1bp1a+tykCJ79uzR9OnT9dRTT+nAgQPW5SA+YhEAGP7w2iWXXKL7779fY8aMUSJh+e3bSKfjx4/r+eef1+OPP65Vq1ZZl4N4SGvDIAAAaTJ48GD95Cc/0dixY61LQciWLFmiadOmadGiRdalINoiHQAY/vDOwIED9ZOf/EQ33nijdSkwtn79ek2bNk1/+tOf+JwAmiptc5oAAKRIbm6uHnnkEd1yyy0c9aOGbdu26aGHHtLs2bOVTCaty0G0RDIAMPzhhVatWumuu+7SD3/4Q7Vp08a6HDhs+/bt+t73vqe5c+dal4JoScus9vNXhQEpMmHCBG3evFkPP/wwwx/16tmzpyZNmmRdBiBJykzTn8u7f8Taeeedp+nTp2vMmDHWpQCIv0BpOAXgBABohEQiodtvv12bNm1i+AOItHSdAACx06tXLz3zzDMaMWKEdSkA0GzpOAHg+B+xM3nyZK1Zs4bhD8BKymcrJwDAGbRv315PPvmkbrrpJutSACClUh0AePeP2Ljiiiv03HPP6YILLrAuBQCkFH8YkA8BArW48847tXTpUoY/gNjiEQBwirPOOktPPvmkJk+ebF0KAKRVKgMAx/+ItK5du+q///u/NWzYMOtSAKAuKXsMwAkAIOmyyy7TK6+8otzcXOtSACAUqfoMAO/+EVnXX3+9Fi9ezPAHEBUpmbl8CBBe+/KXv6x58+YpOzvbuhQACBUBAN6aOnWqZsyYocxMnoQB8E8qOh/H/4icX/ziF/re975nXQYANFWzPwzIWx9451e/+pWmTJliXQYAmGruIwDe/SNSfvGLXzD8AcRFs2YwnwGAN6ZNm8axPwB8hAAALzz88MOaOnWqdRkA4IzmBACO/xEJd9xxh+69917rMgAgHZo8izkBQKz9+7//u377299alwEAziEAILauuuoqzZ49WxkZbHMA+KSmdkaO/+G0vn37at68eWrVqpV1KQCQbk2aybw1Quy0b99ec+fOVceOHa1LAQBnEQAQK4lEQrNmzVLv3r2tSwEApzXlmwA5/oezfvzjH2vMmDHWZXihsrJS27dvV1FRkXbv3q09e/Zo9+7d2r9/vw4dOlS9PvzwQ1VWVlavFi1aKCsrq3q1bt1a7dq1q14dOnRQbm6ucnJylJOTo65du+rCCy9U9+7dlZWVZf3XBlzV6K8G5quAERsFBQW6//77rcuIpbKyMq1atUorVqzQihUrtHHjRu3YsUPJZLLRf1YymVQymdQHH3wgSTp48GCD/nctWrRQt27d1KNHD+Xn56t///769Kc/rfz8fLVr167RdQC+IwAgFrp3765Zs2YpkWjW78bARyoqKlRYWKjFixersLBQb7/9toLA9vCvqqpKxcXFKi4uVmFhYfV/n0gk1Lt3bw0bNkyXXXaZhg0bpkGDBvFbHoF6NPYO4fgfzsnIyNCzzz6rDh06WJcSaWVlZZo3b57mzJmj1157rfoduuuCINCWLVu0ZcsWPfvss5Kktm3bauTIkRo1apSuueYaDRw4kHAIHzTqMQARGZF39913a+TIkdZlRFJVVZVee+01zZgxQ3PnztXx48etS0qJI0eOaMGCBVqwYIEkKTc3VwUFBRozZoyuvfZaZWdnG1cIRE/AYrm0hgwZEpw4cSJA45SVlQWPPfZY0L17d/NrGPY6++yzgwkTJgQvvfRS8MEHH4T+2r/00kvmrwEr1ittrP9iLFb1atWqVbB58+bQG3iU7d27N5gyZUrQunVr8+vnwmrbtm0wadKkoLCwMDh58mQo14AAwErzSgvrvxSLVWM98sgjoTTsOPjHP/4RTJ06NcjOzja/bq6unj17Bg8//HCwZ8+etF4LAgArhJVy1n8hFqt65efnc/TfAMlkMvjd734XdOzY0fyaRWVlZmYGX/ziF4O//e1vabkmBABWCKtB+CZARE4ikdBTTz3Fl8LUY/ny5Ro0aJDuuOMOlZWVWZcTGclkUi+88IKuvPJKDR06VLNnz27S9x0ArmtoAGhwogDS7fbbb9dnPvMZ6zKc9cEHH2jq1Km66qqrtGHDButyIm3lypWaOHGievXqpenTp+vDDz+0LgloiJTObOvjDBYrkBR07tw5KCsrS8vRbBysXbs26NOnj/l1iuvKyckJpk2bFhw7dqzJ14hHAKyQVr14BIBI+fGPf8wX/tTh6aef1uWXX64tW7ZYlxJbe/fu1d13362ePXvq97//vU6cOGFdEpB21kmGxQp69erFB/9qcfz48WDy5Mnm18fHdcEFFwQzZswIqqqqGny9OAFghbTq1ZATgAb9QUC6/fznP+eDf59w8OBBXXfddZoxY4Z1KV4qLi7W5MmTdemll2rx4sXW5QCnqnd28wgAkXDllVfq3/7t36zLcEpxcbEuv/xyLV261LoU761Zs0ajRo3SjTfeqKKiIutygAYhACASfvazn1mX4JTNmzdr+PDh2rZtm3UpOMXcuXPVv39/3XfffaqoqLAuBzgjAgCcd/XVV+uqq66yLsMZ69ev14gRI7R7927rUlCLEydO6JFHHlG/fv00b94863KAOtUXAHj+D3P33XefdQnO2Lp1q6677jodOHDAuhTUY9euXRo3bpzGjh1LWIOVM85wTgDgtMsuu0yf/exnrctwwnvvvafPfvaz2rdvn3UpaIT58+crPz9ff/jDHxQEvKeCOwgAcNp//ud/WpfghMOHD+v666/Xu+++a10KmuDw4cP6xje+oWuuuYYPCcIZiXr+/8RVmMnPz9f69euVSNS3TeOtqqpKN9xwg/73f//XuhQA0VNnAz3TCQDDH6a+/e1vez/8JWnKlCkMfwBNVecsP1N3JQDATNu2bVVSUqI2bdpYl2Lq+eef10033WRdBoBoq3XW8xkAOOnLX/6y98O/qKhIt912m3UZAGKKEwA4aePGjerXr591GWYqKyt12WWXae3atdalAIi+Rp0AMPxhZuTIkV4Pf0n66U9/yvAHkCq1znQeAcA5t9xyi3UJplavXq1HH33UugwAMVfXIwBOAGCiVatW2rt3r9q3b29diomqqioNHTpUa9assS4FQLycNu85AYBTCgoKvB3+kvTkk08y/AGEggAAp9x8883WJZg5cOAA33wIIDS1BQCO/2GiY8eO+vznP29dhpkHHnhAhw4dsi4DQDydNts5AYAzxo4dq5YtW1qXYWLnzp166qmnrMsA4BECAJwxZswY6xLM3H///aqsrLQuA4BHavspAB4BIHQtW7bUgQMH1K5dO+tSQrdt2zb16dNHJ0+etC4FQLzVmPmcAMAJI0eO9HL4S9Jjjz3G8AcQOgIAnFBQUGBdgom9e/dq5syZ1mUA8NAnAwDH/zBxww03WJdgYvr06Tp+/Lh1GQD8UGPGf/IzAAQAhK579+7atWuXdRmhSyaTysvLU0lJiXUpAPxRPfd5BABzI0eOtC7BxIIFCxj+AMwQAGDO1wDw9NNPW5cAwGM8AoC5rVu36qKLLrIuI1T/+Mc/lJubq2QyaV0KAL/wCABuyM3N9W74S9KLL77I8Adg6tQAwLt/hG748OHWJZh47rnnrEsA4KfqWc8JAExdeuml1iWE7sCBA1q2bJl1GQA8RwCAqSFDhliXELqFCxfyzX8AzBEAYGrw4MHWJYRu/vz51iUAQI2fAuAzAAhVXl6eiouLrcsIVVVVlTp16qTDhw9blwLAXwmJEwAY8vH4f/Xq1Qx/AE4gAMDMwIEDrUsI3eLFi61LAABJBAAY6tu3r3UJoVuyZIl1CQAg6eMAwPN/hK5Xr17WJYTu//7v/6xLAIBA4gQAhnwLANu3b1dZWZl1GQAgiQAAI7m5uWrbtq11GaFasWKFdQkAUI0AABO+vfuXpFWrVlmXAADVCAAw4eMvANqwYYN1CQBQjQAAE926dbMuIXSbNm2yLgEAqhEAYKJr167WJYTq6NGjeu+996zLAIBqBACY8C0AbNmyRUHAT9sCcAcBACZ8CwC+/c4DAO4jAMDEeeedZ11CqAgAAFxDAEDoWrRooS5duliXEapdu3ZZlwAANRAAELpOnTopI8Ovrffuu+9alwAANWSI3wOAkLVv3966hNDt27fPugQAOFXg19swOKFDhw7WJYTuwIED1iUAQA0EAITOxxOA/fv3W5cAADUQABA63wLA8ePHdeTIEesyAKAGAgBC51sAOHz4sHUJAHAaAgBC59uvAebdPwAXEQAQupYtW1qXECoCAAAXEQAQuqysLOsSQnX06FHrEgDgNAQAhM63AHDixAnrEgDgNAQAhM63AJBMJq1LAIDTEAAQOgIAANgjACB0BAAAsEcAQOgSiYR1CaEKAn7dBgD3EAAQusrKSusSQpWZmWldAgCchgCA0BEAAMAeAQChIwAAgD0CAELnWwDw7UOPAKKBAIDQ+RYA2rRpY10CAJyGAIDQ+fbNeL798iMA0UAAQOh8+258AgAAFxEAELry8nLrEkLVrl076xIA4DQEAITOtwBw9tlnKzs727oMAKiBAIDQ+RYAJOlTn/qUdQkAUAMBAKE7dOiQdQmhIwAAcA0BAKHjBAAA7BEAELrS0lLvfkFO9+7drUsAgBoIAAhdZWWlDh48aF1GqPLy8qxLAIAaCAAwsWfPHusSQnXBBRdYlwAANRAAYKKkpMS6hFARAAC4hgAAE74FgD59+liXAAA1EABgwrcA0L59e5133nnWZQBANQIATOzevdu6hND169fPugQAqJYhKWFdBPyzbds26xJCl5+fb10CAPxLghMAmCgqKrIuIXSXXHKJdQkAUI0AABN79uxRRUWFdRmhGjp0qHUJAFCNAAATQRB49xigd+/e/GpgAM4gAMCMb48BEomEhg0bZl0GAEgiAMDQli1brEsI3dVXX21dAgBIIgDA0Lp166xLCN0111xjXQIASPr4RwD9+tVscMJFF12krVu3WpcRqsrKSnXq1ElHjx61LgWA3/gxQNjZvn27ysvLrcsIVVZWlq699lrrMgCARwCwEwSB1q5da11G6MaMGWNdAgAQAGBr9erV1iWE7oYbblAiwRdwArBFAICplStXWpcQupycHF1++eXWZQDw3L8CAG9HYOKvf/2rdQkm/uM//sO6BAD+SlT/n4/wkwAwsXPnTl1wwQXWZYRq3759Ou+881RVVWVdCgD/JCQeAcABf/nLX6xLCN25557LTwMAMEUAgDkfA4Ak3XbbbdYlAPAYjwBgrmfPnt79YiDpn18K1L17d+3du9e6FAB+4REA3LB9+3bt2rXLuozQZWVl6atf/ap1GQA8RQCAE1599VXrEkx861vfUsuWLa3LAOAhAgCcsGDBAusSTHTt2lWTJk2yLgOAhz758/98DgAmzjrrLB08eFCtW7e2LiV0W7ZsUb9+/XTy5EnrUgDEX/Xc5wQATjh+/Lhef/116zJM9OnTR1/60pesywDgGQIAnDF//nzrEsw8+OCDyszMtC4DgEcIAHDG3LlzVVlZaV2GiYsuukhf+9rXrMsA4BE+AwCnzJ8/XwUFBdZlmNi3b5/69Omj8vJy61IAxBefAYCbZs+ebV2CmXPPPVcPPvigdRkAPFHbbwHkFABmsrOztW/fPrVp08a6FBNVVVUaMmSI1q1bZ10KgPipMfM5AYBTKioqNGfOHOsyzLRo0ULPPPOMWrRoYV0KgJgjAMA5M2fOtC7B1NChQ/WDH/zAugwAMccjADgnkUho8+bN6t27t3UpZk6cOKGhQ4fyKABAKvEIAG4LgkBPPPGEdRmmWrZsqT//+c9efjMigHBwAgAntW/fXiUlJcrOzrYuxdTs2bM1ceJE6zIAxEO9JwC1hQIgVOXl5V7/SOC/3HzzzfrmN79pXQaA6Dttttc17DkFgLkBAwbo7bffti7DXDKZ1PXXX+/t70oAkBKnzXs+AwBnrVu3TosWLbIuw1xmZqZefPFF9e3b17oUNNOIESP0yCOPWJcBSCIAwHEPPfSQdQlO6NChg/7nf/5H559/vnUpaIK2bdvqiSee0JIlS7z+6Ra4hQAApy1btkxLliyxLsMJeXl5ev3119WlSxfrUtAIBQUF2rhxo775zW8qkeAjVnBHXQGAXQpncArwsT59+ui1117TOeecY10K6pGXl6c5c+Zo/vz56tatm3U58FutM50TADjvjTfe0PLly63LcMagQYP0l7/8Rbm5udaloBYtW7bUPffco02bNunGG2+0LgeoEwEAkXDPPfdYl+CU/Px8vfnmm7rwwgutS8Epxo4dq/Xr1+vRRx/1/jss4D4CACJh6dKlmjdvnnUZTunZs6feeustXXnlldaleG/gwIF64403NHfuXD7kh8g4UwDgcwBwyg9+8AMlk0nrMpzSpUsXvfHGG3xboJG8vDz98Y9/1OrVqzVq1CjrcoDa1DnLOQFAZGzevFlPP/20dRnOOeusszRr1iw98cQTOuuss6zL8UJOTo4ef/xxFRUV6dZbb1VGBq0U8ROwWC6tT33qU0F5eXmA2q1evTro1auX+XWK6zr33HODadOmBceOHWvyNXrppZfM/x4sr1adiK2IlP379+vee++1LsNZgwcP1tq1a/Xd736Xd6UplJeXp9///vcqLi7W1KlT+YAfvGGdXlisGisjIyNYvnx5Ct83x9Obb74Z9OvXz/x6RXldcsklwbPPPhtUVlam7LpwAsAKcZ0RbxEQOSdPntTtt9/OBwLrcdVVV+ntt9/Wb37zG3Xo0MG6nMjIzMzUF77wBf31r3/VypUrNWnSJGVmZlqXBaQcAQCRtG7dOv3qV7+yLsN5mZmZuvPOO1VUVKS77rpLZ599tnVJzurRo4ceeughFRcX64UXXuDHKwHZH2GwWLWu7OzsoKioKGVHsz4oKSkJvvOd7wTZ2dnm18+F1aZNm2DixInBG2+8EZw8eTKUa8AjAFaIKyWs/xIsVq1r6NChKX0+64vS0tLgZz/7WXD++eebX8OwV6tWrYLx48cHL774YlBRURH6a08AYIW0Usb6L8Ji1bnuu+++0Jt4XCSTyWDBggXBhAkTgpYtW5pfy3St3Nzc4Gtf+1rwyiuvNOtH+FKBAMAKadWrod/216A/DLCQkZGhJUuWaPjw4dalRFppaaleeeUVzZkzR6+//ro+/PBD65KarG3btho+fLhGjRqlUaNGadCgQc78Kt6XX35ZEyZMsC4D8VfvhicAIBby8vL09ttvq3379talxMLRo0dVWFioxYsXq7CwUOvXr1cQuNsGevXqpWHDhlWvwYMHO/vJfQIAQpKyACARAuC4cePGac6cOc6804uT0tJSrVy5UitWrNDKlSu1YcMG7dy5U1VVVaHVkJGRoW7duqlHjx7Kz8/Xpz/96eoVpeBHAEAIGtQECQCIlQcffFA/+tGPrMvwwokTJ7Rt2zYVFRVp9+7d2rNnj3bv3q0DBw6orKxMhw4d0qFDh/Thhx+qsrJSlZWVSiaTatGihbKyspSVlaXMzEy1bt1a7dq1q16dOnVSTk5O9crNzVWPHj2Ul5enrKws6792sxEAEAICAPyTSCQ0f/583XDDDdalALUiACAEDZrtjfkiIM5V4bwgCHTzzTdr69at1qUAgIUGz2q+CRCxU15ernHjxqmsrMy6FABwFgEAsfTOO+9o3LhxOn78uHUpAOAkAgBi680339TEiRN18uRJ61IAwDmNDQB8DgCR8tJLL2nKlCnWZQBAGBo1ozkBQOw9/vjjevTRR63LAACnEADghXvvvVePPfaYdRkA4IymBAAeAyCS7r77bv3yl7+0LgMA0qHRs5kTAHjl+9//vn79619blwEA5ggA8M5dd93FSQAA7zU1APAYAJH2/e9/X/fcc491GQCQCk2ayZwAwFs///nPNXnyZCWTSetSACB0BAB4bebMmRo3bpwqKiqsSwGAUDUnAPAYALGwcOFCjRo1Su+//751KQDQWE2exZwAAJLeeustXXrppfr73/9uXQoAhIIAAHykpKREI0aM0MyZM61LAYC0a24A4DEAYuX48eOaPHmypkyZwocDAbiuWTOYEwCgFr/5zW80YsQIFRcXW5cCAGmRigDAKQBiafny5Ro0aJCef/5561IA4JOaPXs5AQDOoLy8XDfddJO++tWv6tixY9blAEDKEACABvjjH/+owYMH680337QuBQBSIlUBgMcAiL2tW7dq5MiR+ta3vqXDhw9blwPAXymZuZwAAI0QBIGmT5+u/Px8LViwwLocAGiyVAYATgHgjd27d2vMmDH64he/qF27dlmXA8AfKZu1nAAAzfDiiy+qb9+++tGPfsSHBFGvHTt2aNasWdZlAJJS/649SPGfB0RG165d9eijj2rSpElKJDgQw8e2b9+uhx9+WLNmzeILptBcKWsu6ehShAB4bdCgQXrggQc0duxY61JgbMOGDZo2bZqee+45VVVVWZeD6EvpzCYAAGkyZMgQPfDAAyooKLAuBSFbunSppk2bpoULFyoIaIlIGecDgEQIAKpdeumluv/++1VQUMCjgRg7ceKEXnjhBT3++ONasWKFdTmIn5Q3DwIAEJLevXvrzjvv1C233KLWrVtbl4MUKSkp0ZNPPqk//OEP2r9/v3U5iC8CABB1HTt21Ne//nV9+9vfVrdu3azLQRNUVVVp0aJFeuaZZ/Tqq6/ywT6EITIBQCIEAGeUmZmp66+/XrfeeqsKCgqUlZVlXRLqsXnzZs2aNUszZsxQSUmJdTnwR1pmNQEAcECXLl00ceJE3Xrrrerfv791OTjF3r179ec//1n/9V//pVWrVlmXAz9FLgBIhACg0QYNGqQJEyZo/Pjx6tu3r3U5XtqzZ4/mzJmjl19+WUuXLtXJkyetS4K/0janCQCAw/Lz8zV+/HiNHz9eAwYMsC4n1jZs2KBXX31Vr7zyit566y1+fA+uiGwAkAgBQEp069ZNo0eP1ujRo3XttdfqnHPOsS4p0srLy7VkyRItWrRICxcu1HvvvWddEvBJaZ3RBAAggjIyMjRkyBBdd911GjlypIYNG6YOHTpYl+W0I0eOaPny5Vq8eLEKCwu1atUqvp0Prot8AJAIAUBaJRIJXXzxxfrMZz6jK664QldccYX69OmjjAw/f99XEATaunWr/v73v2vZsmVavny51q9fz8BHlKR9PhMAgJhq3bq18vPz1b9/fw0YMED9+/dX//791blzZ+vSUurw4cPavHmzNm7cqLVr12rNmjVau3atjhw5Yl0a0ByxCQASIQBwQpcuXdSzZ0/16NFDPXr0qP7nCy+8UDk5OU5+H0F5ebmKi4u1Y8cO7dy5Uzt27FBRUZHeeecd7d6927o8INVCmc0EAADVEomEzjnnHOXk5CgnJ0fnnnuucnJy1LlzZ7Vv317t2rWrsdq2bauzzz5bmZmZysrKqvGfmZmZkv75rXnJZLL6PysqKnTs2LHqdeTIEZWVlengwYMqLS3VwYMHtX//fpWUlFSvY8eOGb8yQKhiFwAkQgAAAGcS2lz28xNCAAB4LuwAwO9CBQCgdqHOSE4AAADwkEUA4BQAAICaQp+NnAAAAOAhqwDAKQAAAP9kMhM5AQAAwEOWAYBTAACA78xmIScAAAB4yDoAcAoAAPCV6Qy0DgAAAMCACwGAUwAAgG/MZ58LAUBy4IUAACAkTsw8VwIAAAAIkUsBwIlEBABAGjkz61wKAAAAICSuBQBnkhEAACnm1IxzLQAAAIAQuBgAnEpIAACkgHOzzcUAIDn4QgEA0EROzjRXAwAAAEgjlwOAk4kJAIBGcHaWuRwAJIdfOAAA6uH0DHM9AAAAgDSIQgBwOkEBAFAL52dXFAIAAABIsagEAOeTFAAAH4nEzIpKAJAi8oICALwWmVkVpQAAAABSJGoBIDLJCgDgnUjNqKgFACliLzAAwAuRm01RDAAAAKCZohoAIpe0AACxFcmZFNUAIEX0BQcAxEpkZ1GUA4AU4RceABB5kZ5BUQ8AAACgCeIQACKdwAAAkRT52ROHACDF4EIAACIjFjMnLgFAiskFAQA4LTazJk4BAAAANFDcAkBskhkAwDmxmjFxCwBSzC4QAMAJsZstcQwAUgwvFADATCxnSlwDAAAAOIM4B4BYJjYAQKhiO0viHACkGF84AEDaxXqGxD0ASDG/gACAtIj97PAhAEgeXEgAQMp4MTN8CQAAAOAUPgUALxIdAKBZvJkVPgUAyaMLCwBoNK9mhG8BQPLsAgMAGsS72eBjAJA8vNAAgDp5ORN8DQCSpxccAFCDt7PA5wAAAIC3fA8A3iY/AIDfM8D3ACB5vgEAwFPe934CwD95vxEAwCP0fBEATsWGAID4o9d/hABQExsDAOKLHn8KAsDp2CAAED/09k8gANSOjQIA8UFPrwUBoG5sGACIPnp5HQgAZ8bGAYDoooefAQGgfmwgAIgeenc9CAANw0YCgOigZzcAAaDh2FAA4D56dQMRABqHjQUA7qJHNwIBoPHYYADgHnpzIxEAmoaNBgDuoCc3AQGg6dhwAGCPXtxEBIDmYeMBgB16cDMQAJqPDQgA4aP3NhMBIDXYiAAQHnpuChAAUocNCQDpR69NEQJAarExASB96LEpRABIPTYoAKQevTXFCADpwUYFgNShp6YBASB92LAA0Hz00jThhQ1HYF0AAEQM8ynNOAEIBxsZABqOnhkCAkB42NAAUD96ZUgIAOFiYwNA3eiRISIAhI8NDgCnozeGjBfcFh8OBOA75pARTgBssfEB+IweaIgAYI8bAICP6H3GCABu4EYA4BN6ngO4CO7hcwEA4oqZ4xBOANzDDQIgjuhtjiEAuIkbBUCc0NMcxEVxH48EAEQVM8ZhnAC4jxsIQBTRuxxHAIgGbiQAUULPigAuUvTwSACAq5gpEcIJQPRwgwFwEb0pYggA0cSNBsAl9KQI4qJFH48EAFhhhkQYJwDRxw0IwAK9J+K4gPHCaQCAdGNuxAQnAPHCjQkgnegxMcLFjC9OAwCkCrMihrio8UcQANBUzIgY4xFA/HEDA2gKekfMcYH9wmkAgPowFzzBCYBfuLEBnAk9wiNcbH9xGgDgX5gFHuKigyAA+IsZ4DEuPv6FIAD4g94PPgOAajQEwA/c65DERkDtOA0A4od+jxrYEDgTggAQffR51IqNgYYgCADRQ3/HGbFB0BgEAcB99HU0CBsFTUEQANxDP0ejsGHQHAQBwB59HE3CxkEqEASA8NG/0SxsIKQSQQBIP/o2UoKNhHQgCACpR79GSrGhkE4EAaD56NNICzYWwkAQABqP/oy0YoMhbIQBoG70ZISGzQYrBAHgY/RihI5NBxcQBuAj+i9MsQHhEoIAfEDfhRPYiHAVYQBxQq+Fc9iUcB1BAFFGj4Wz2JyIEsIAooC+ikhgoyKqCANwCb0UkcOmRRwQBmCB/olIYwMjbggDSCd6JmKDzYy4IxCgOeiRiC02N3xCGEBD0BfhBTY6fEYggEQfhKfY+MDHCAR+oO8B4kYAzoRAEA/0OaAW3BhAwxEIooG+BjQANwrQPIQCW/QwoIm4eYD0IBikFr0KSDFuKiBcBIMzoycBIeFmA9wS94BAzwEcwc0IRJt1YKCHABH1/7lgrbtlbAK5AAAAAElFTkSuQmCC">
    <link rel="shortcut icon" href="data:image/png;base64,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">
    <link rel="apple-touch-icon" href="data:image/png;base64,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">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        :root {
            --bg: #0d1117; --card-bg: #161b22; --border: #30363d;
            --text: #c9d1d9; --text-muted: #8b949e; --accent: #58a6ff;
            --green: #238636; --red: #da3633; --yellow: #d29922; --purple: #8957e5;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); padding: 24px; }
        .container { max-width: 1080px; margin: 0 auto; }
        header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 20px; border-bottom: 1px solid var(--border); margin-bottom: 24px; }
        h1 { font-size: 22px; font-weight: 600; }
        .nav-tabs { display: flex; gap: 12px; margin-bottom: 20px; }
        .tab-btn { background: none; border: none; color: var(--text-muted); font-size: 15px; font-weight: 500; padding: 8px 16px; cursor: pointer; border-bottom: 2px solid transparent; }
        .tab-btn.active { color: var(--text); border-bottom-color: var(--accent); }
        .btn { background: var(--card-bg); border: 1px solid var(--border); color: var(--text); padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 14px; text-decoration: none; display: inline-flex; align-items: center; gap: 6px; }
        .btn:hover { background: #21262d; border-color: #8b949e; }
        .btn-primary { background: var(--green); border-color: rgba(240,246,252,0.1); color: #fff; }
        .btn-primary:hover { background: #2ea043; }
        .btn-purple { background: var(--purple); border-color: rgba(240,246,252,0.1); color: #fff; }
        .btn-purple:hover { background: #9a67ea; }
        .btn-danger { color: #f85149; border-color: rgba(240,246,252,0.1); }
        .btn-danger:hover { background: var(--red); color: #fff; }
        .btn-sm { padding: 4px 10px; font-size: 12px; }
        .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 24px; }
        .table { width: 100%; border-collapse: collapse; margin-top: 12px; }
        .table th, .table td { text-align: left; padding: 12px; border-bottom: 1px solid var(--border); font-size: 14px; }
        .table th { color: var(--text-muted); font-weight: 500; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 12px; font-weight: 500; }
        .badge-active { background: rgba(35,134,54,0.2); color: #3fb950; border: 1px solid rgba(63,185,80,0.3); }
        .badge-cooling { background: rgba(210,153,34,0.2); color: #f2cc60; border: 1px solid rgba(242,204,96,0.3); }
        .badge-disabled { background: rgba(110,118,129,0.2); color: #8b949e; border: 1px solid rgba(139,148,158,0.3); }
        .badge-official { background: rgba(88,166,255,0.2); color: #58a6ff; border: 1px solid rgba(88,166,255,0.3); }
        .badge-community { background: rgba(137,87,229,0.2); color: #bc8cff; border: 1px solid rgba(137,87,229,0.3); }
        .modal-bg { position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; background: rgba(0,0,0,0.7); display: none; justify-content: center; align-items: center; z-index: 100; }
        .modal { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; width: 520px; padding: 24px; box-shadow: 0 8px 24px rgba(0,0,0,0.5); }
        .code-block { background: #0d1117; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 14px; word-break: break-all; margin: 12px 0; border: 1px solid var(--border); }
        input[type="text"], textarea { width: 100%; background: #0d1117; border: 1px solid var(--border); color: var(--text); padding: 10px; border-radius: 6px; font-size: 14px; margin-top: 8px; font-family: monospace; }
        input[type="text"]:focus, textarea:focus { border-color: var(--accent); outline: none; }
    </style>
</head>
<body>
<div class="container">
    <header>
        <div>
            <div style="display: flex; align-items: center; gap: 12px;">
                <img src="/favicon.ico" alt="Logo" style="width: 32px; height: 32px; border-radius: 6px; box-shadow: 0 2px 6px rgba(0,0,0,0.3);">
                <h1>Cline2API 管理控制台</h1>
            </div>
            <p style="color: var(--text-muted); font-size: 13px; margin-top: 4px;">本地轻量网关 · 自动协议转换 · 官方免费模型雷达监控</p>
        </div>
        <div style="display: flex; gap: 10px;">
            <button class="btn btn-purple" onclick="openImportModal()">📥 导入 RefreshToken</button>
            <button class="btn btn-primary" onclick="startOAuth()">+ 设备码授权</button>
        </div>
    </header>

    <div class="nav-tabs">
        <button class="tab-btn active" id="tabBtnAccounts" onclick="switchTab('accounts')">👥 账号池管理</button>
        <button class="tab-btn" id="tabBtnModels" onclick="switchTab('models')">⚡ 免费模型雷达</button>
    </div>

    <!-- 视图 1：账号管理 -->
    <div id="viewAccounts">
        <div class="card">
            <h2 style="font-size: 16px; margin-bottom: 12px;">网关访问接入点</h2>
            <div style="font-size: 14px; line-height: 1.8;">
                <div><strong>Base URL：</strong> <code style="color: var(--accent);">http://127.0.0.1:18091/v1</code></div>
                <div><strong>API 密钥：</strong> <code id="apiKeyText" style="color: var(--accent);">加载中...</code></div>
            </div>
        </div>

        <div class="card">
            <h2 style="font-size: 16px; margin-bottom: 8px;">已接入账号池 (<span id="accCount">0</span>)</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>邮箱 / 标识</th>
                        <th>状态</th>
                        <th>冷却倒计时</th>
                        <th>AccessToken 状态</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody id="accTable">
                    <tr><td colspan="5" style="text-align: center; color: var(--text-muted);">正在加载账号...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <!-- 视图 2：免费模型监控 -->
    <div id="viewModels" style="display: none;">
        <div class="card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                <div>
                    <h2 style="font-size: 16px;">实时可用免费模型监控</h2>
                    <p style="color: var(--text-muted); font-size: 13px; margin-top: 4px;">与 Cline 官方客户端 Free 列表完全对齐并实时探活</p>
                </div>
                <button class="btn btn-sm" onclick="loadFreeModels()">🔄 刷新模型列表</button>
            </div>
            <table class="table">
                <thead>
                    <tr>
                        <th>客户端显示名称</th>
                        <th>真实模型 ID</th>
                        <th>类型分类</th>
                        <th>描述</th>
                        <th>探活状态</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody id="modelsTable">
                    <tr><td colspan="6" style="text-align: center; color: var(--text-muted);">正在拉取模型目录...</td></tr>
                </tbody>
            </table>
        </div>
    </div>
</div>

<!-- 弹窗 1：手动导入 RefreshToken -->
<div class="modal-bg" id="importModal">
    <div class="modal">
        <h3 style="margin-bottom: 12px;">手动导入 RefreshToken</h3>
        <p style="color: var(--text-muted); font-size: 14px;">支持单账号或多账号（一行一个），自动尝试解析并换取凭据：</p>
        
        <div style="margin-top: 14px;">
            <label style="font-size: 13px; color: var(--text-muted);">账号邮箱 (可选备注，多账号时可留空)：</label>
            <input type="text" id="importEmail" placeholder="例如：myaccount@gmail.com">
        </div>

        <div style="margin-top: 12px;">
            <label style="font-size: 13px; color: var(--text-muted);">RefreshToken (必填，支持多行)：</label>
            <textarea id="importTokens" rows="4" placeholder="在此粘贴你的 refreshToken 字符串..."></textarea>
        </div>

        <div style="display: flex; justify-content: flex-end; gap: 10px; margin-top: 20px;">
            <button class="btn" onclick="closeImportModal()">取消</button>
            <button class="btn btn-primary" onclick="submitImportTokens()">确认导入</button>
        </div>
    </div>
</div>

<!-- 弹窗 2：OAuth 设备码 -->
<div class="modal-bg" id="oauthModal">
    <div class="modal">
        <h3 style="margin-bottom: 12px;">Cline WorkOS 设备码授权</h3>
        <p style="color: var(--text-muted); font-size: 14px;">在干净的网络环境下打开下方链接并授权：</p>
        
        <div style="margin-top: 14px;">
            <div style="font-size: 12px; color: var(--text-muted);">设备码 (User Code)：</div>
            <div class="code-block" id="userCodeText" style="font-size: 18px; font-weight: bold; color: var(--accent);">-</div>
        </div>

        <div style="margin-top: 8px;">
            <div style="font-size: 12px; color: var(--text-muted);">授权链接：</div>
            <div class="code-block"><a id="authLink" href="#" target="_blank" style="color: var(--accent); text-decoration: none;">点击直达授权页面</a></div>
        </div>

        <div id="oauthStatus" style="font-size: 13px; color: var(--yellow); margin-top: 14px;">
            ⏳ 正在等待浏览器授权... (自动轮询中)
        </div>

        <div style="text-align: right; margin-top: 20px;">
            <button class="btn" onclick="closeOAuth()">关闭</button>
        </div>
    </div>
</div>

<script>
let oauthPollTimer = null;

function switchTab(tab) {
    if (tab === 'accounts') {
        document.getElementById('viewAccounts').style.display = 'block';
        document.getElementById('viewModels').style.display = 'none';
        document.getElementById('tabBtnAccounts').classList.add('active');
        document.getElementById('tabBtnModels').classList.remove('active');
    } else {
        document.getElementById('viewAccounts').style.display = 'none';
        document.getElementById('viewModels').style.display = 'block';
        document.getElementById('tabBtnAccounts').classList.remove('active');
        document.getElementById('tabBtnModels').classList.add('active');
        loadFreeModels();
    }
}

async function loadData() {
    try {
        const r = await fetch('/admin/api/status');
        const data = await r.json();
        document.getElementById('apiKeyText').innerText = data.api_key;
        document.getElementById('accCount').innerText = data.accounts.length;

        const tbody = document.getElementById('accTable');
        if (data.accounts.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">暂无已授权账号，请点击右上角「导入 RefreshToken」或「设备码授权」</td></tr>';
            return;
        }

        const now = Math.floor(Date.now() / 1000);
        tbody.innerHTML = data.accounts.map(a => {
            const isCooling = (a.cooldownUntil || 0) > now;
            const isEnabled = a.enabled !== false;
            let statusBadge = '<span class="badge badge-active">正常可用</span>';
            if (!isEnabled) {
                statusBadge = '<span class="badge badge-disabled">已禁用</span>';
            } else if (isCooling) {
                statusBadge = '<span class="badge badge-cooling">限流冷却</span>';
            }

            const cdSec = isCooling ? (a.cooldownUntil - now) : 0;
            const cdText = cdSec > 0 ? `${Math.floor(cdSec / 60)}分${cdSec % 60}秒` : '-';
            const atState = a.expiry > now ? `<span style="color: #3fb950;">已缓存 (至 ${new Date(a.expiry * 1000).toLocaleTimeString()})</span>` : '<span style="color: var(--text-muted);">待请求时自动刷新</span>';

            return `<tr>
                <td><strong>${a.email || '未知邮箱'}</strong></td>
                <td>${statusBadge}</td>
                <td>${cdText}</td>
                <td>${atState}</td>
                <td style="display: flex; gap: 8px;">
                    <button class="btn btn-sm" onclick="toggleAccount('${a.id}')">${isEnabled ? '禁用' : '启用'}</button>
                    <button class="btn btn-sm" onclick="reauthAccount('${a.id}')">重登录</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteAccount('${a.id}')">删除</button>
                </td>
            </tr>`;
        }).join('');
    } catch (e) {
        console.error(e);
    }
}

async function loadFreeModels() {
    const tbody = document.getElementById('modelsTable');
    tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">⏳ 正在通过账号拉取官方与开源免费模型列表...</td></tr>';
    try {
        const res = await fetch('/admin/api/free-models');
        const data = await res.json();
        if (data.status !== 'success' || !data.models || data.models.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: #f85149;">${data.message || '暂无可用免费模型'}</td></tr>`;
            return;
        }

        tbody.innerHTML = data.models.map(m => {
            const badgeClass = m.source === 'official_free' ? 'badge-official' : 'badge-community';
            return `<tr>
                <td><strong style="color: #f0f6fc;">${m.name}</strong></td>
                <td><code style="color: var(--accent); font-family: monospace;">${m.id}</code></td>
                <td><span class="badge ${badgeClass}">${m.type}</span></td>
                <td style="color: var(--text-muted); font-size: 13px;">${m.description}</td>
                <td id="probe-${m.id.replace(/[^a-zA-Z0-9]/g, '_')}"><span style="color: var(--text-muted); font-size: 12px;">待测试</span></td>
                <td>
                    <button class="btn btn-sm" onclick="testModel('${m.id}')">⚡ 测延迟</button>
                </td>
            </tr>`;
        }).join('');
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: #f85149;">拉取失败: ${e}</td></tr>`;
    }
}

async function testModel(modelId) {
    const elemId = 'probe-' + modelId.replace(/[^a-zA-Z0-9]/g, '_');
    const elem = document.getElementById(elemId);
    elem.innerHTML = '<span style="color: var(--yellow); font-size: 12px;">⏳ 探测中...</span>';
    try {
        const res = await fetch('/admin/api/free-models/test', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({model: modelId})
        });
        const data = await res.json();
        if (data.status === 'success') {
            elem.innerHTML = `<span style="color: #3fb950; font-size: 12px;">✅ 200 OK (${data.latency_ms}ms)</span>`;
        } else {
            elem.innerHTML = `<span style="color: #f85149; font-size: 12px;" title="${data.error || ''}">❌ ${data.http_code || 'Err'} (${data.latency_ms || 0}ms)</span>`;
        }
    } catch (e) {
        elem.innerHTML = `<span style="color: #f85149; font-size: 12px;">❌ 探活异常</span>`;
    }
}

// 导入 RefreshToken
function openImportModal() {
    document.getElementById('importModal').style.display = 'flex';
}
function closeImportModal() {
    document.getElementById('importModal').style.display = 'none';
}
async function submitImportTokens() {
    const email = document.getElementById('importEmail').value.trim();
    const rawTokens = document.getElementById('importTokens').value.trim();
    if (!rawTokens) {
        alert('请输入至少一个 RefreshToken');
        return;
    }
    try {
        const res = await fetch('/admin/api/account/import', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({email, tokens: rawTokens})
        });
        const data = await res.json();
        if (data.status === 'success') {
            alert(`成功导入 ${data.count} 个账号！`);
            closeImportModal();
            loadData();
        } else {
            alert('导入失败: ' + data.message);
        }
    } catch (e) {
        alert('网络请求出错: ' + e);
    }
}

// OAuth 相关
async function startOAuth() {
    document.getElementById('oauthModal').style.display = 'flex';
    document.getElementById('oauthStatus').innerText = '⏳ 正在向 WorkOS 申请设备授权码...';
    try {
        const res = await fetch('/admin/api/oauth/start', { method: 'POST' });
        const data = await res.json();
        if (data.error) {
            alert('启动授权失败: ' + data.error);
            closeOAuth();
            return;
        }
        document.getElementById('userCodeText').innerText = data.user_code;
        const linkElem = document.getElementById('authLink');
        linkElem.href = data.auth_url;
        linkElem.innerText = data.auth_url;
        document.getElementById('oauthStatus').innerText = '⏳ 请在新窗口中登录并授权... (每 5 秒轮询)';
        window.open(data.auth_url, '_blank');
        pollOAuth(data.session_id);
    } catch (e) {
        alert('网络请求失败: ' + e);
        closeOAuth();
    }
}

function pollOAuth(sessionId) {
    if (oauthPollTimer) clearInterval(oauthPollTimer);
    oauthPollTimer = setInterval(async () => {
        try {
            const res = await fetch(`/admin/api/oauth/poll?session_id=${sessionId}`);
            const data = await res.json();
            if (data.status === 'success') {
                clearInterval(oauthPollTimer);
                document.getElementById('oauthStatus').innerText = '✅ 授权成功！账号已存入池中。';
                setTimeout(() => {
                    closeOAuth();
                    loadData();
                }, 1200);
            } else if (data.status === 'error') {
                clearInterval(oauthPollTimer);
                document.getElementById('oauthStatus').innerText = '❌ 授权失败: ' + data.message;
            }
        } catch (e) {}
    }, 5000);
}

function closeOAuth() {
    if (oauthPollTimer) clearInterval(oauthPollTimer);
    document.getElementById('oauthModal').style.display = 'none';
}

async function toggleAccount(id) {
    await fetch('/admin/api/account/toggle', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({id}) });
    loadData();
}

async function deleteAccount(id) {
    if (!confirm('确定要删除该账号凭据吗？')) return;
    await fetch('/admin/api/account/delete', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({id}) });
    loadData();
}

function reauthAccount(id) {
    startOAuth();
}

loadData();
setInterval(loadData, 5000);
</script>
</body>
</html>
"""

@app.get("/admin", response_class=HTMLResponse)
@app.get("/admin/", response_class=HTMLResponse)
@app.get("/admin/models", response_class=HTMLResponse)
async def admin_page():
    return HTMLResponse(ADMIN_HTML)

@app.get("/admin/api/status")
async def admin_status():
    cfg = load_config()
    accs = load_accounts()
    safe_accs = []
    for a in accs:
        safe_accs.append({
            "id": a.get("id"),
            "email": a.get("email"),
            "enabled": a.get("enabled", True),
            "cooldownUntil": a.get("cooldownUntil", 0),
            "expiry": a.get("expiry", 0),
            "last_error": a.get("last_error", "")
        })
    return {
        "api_key": cfg.get("api_key"),
        "accounts": safe_accs
    }

@app.post("/admin/api/account/import")
async def admin_import_tokens(req: Request):
    """手动直接导入 RefreshToken"""
    data = await req.json()
    raw_tokens = data.get("tokens", "")
    default_email = data.get("email", "")
    tokens = [t.strip() for t in raw_tokens.splitlines() if len(t.strip()) > 8]
    if not tokens:
        return {"status": "error", "message": "未解析到有效的 RefreshToken"}

    accs = load_accounts()
    added_count = 0

    for idx, rt in enumerate(tokens):
        email = default_email if (len(tokens) == 1 and default_email) else f"token_{int(time.time())}_{idx+1}"
        new_acc = {
            "id": str(uuid.uuid4()),
            "email": email,
            "refreshToken": rt,
            "accessToken": None,
            "expiry": 0,
            "enabled": True,
            "cooldownUntil": 0,
            "created_at": int(time.time())
        }
        try:
            url = f"{CLINE_API_BASE}/auth/refresh"
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.post(url, json={"refreshToken": rt, "grantType": "refresh_token"})
                if r.status_code == 200:
                    r_data = r.json().get("data", {})
                    new_acc["accessToken"] = r_data.get("accessToken")
                    new_acc["expiry"] = int(time.time()) + 3000
                    if r_data.get("refreshToken"):
                        new_acc["refreshToken"] = r_data.get("refreshToken")
        except Exception:
            pass

        replaced = False
        for i, a in enumerate(accs):
            if a.get("refreshToken") == rt:
                accs[i] = new_acc
                replaced = True
                break
        if not replaced:
            accs.append(new_acc)
        added_count += 1

    save_accounts(accs)
    return {"status": "success", "count": added_count}

@app.post("/admin/api/oauth/start")
async def admin_oauth_start():
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            r = await client.post(WORKOS_DEVICE_URL, data={"client_id": WORKOS_CLIENT_ID})
            if r.status_code != 200:
                return JSONResponse({"error": f"WorkOS error {r.status_code}: {r.text}"}, status_code=400)
            data = r.json()
            session_id = uuid.uuid4().hex
            auth_url = data.get("verification_uri_complete") or data.get("verification_uri")
            pending_oauth[session_id] = {
                "device_code": data["device_code"],
                "interval": data.get("interval", 5),
                "expires_at": time.time() + data.get("expires_in", 300),
                "status": "pending"
            }
            return {
                "session_id": session_id,
                "user_code": data["user_code"],
                "auth_url": auth_url
            }
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

@app.get("/admin/api/oauth/poll")
async def admin_oauth_poll(session_id: str):
    item = pending_oauth.get(session_id)
    if not item:
        return {"status": "error", "message": "Session expired"}

    if time.time() > item["expires_at"]:
        pending_oauth.pop(session_id, None)
        return {"status": "error", "message": "授权超时，请重试"}

    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            r = await client.post(WORKOS_AUTH_URL, data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": item["device_code"],
                "client_id": WORKOS_CLIENT_ID
            })
            res = r.json()
            if "access_token" in res:
                reg_r = await client.post(f"{CLINE_API_BASE}/auth/register", json={
                    "accessToken": res["access_token"],
                    "refreshToken": res["refresh_token"]
                })
                reg_data = reg_r.json().get("data", {})
                rt = reg_data.get("refreshToken")
                email = (reg_data.get("userInfo") or {}).get("email") or f"user_{int(time.time())}"
                if rt:
                    accs = load_accounts()
                    new_acc = {
                        "id": str(uuid.uuid4()),
                        "email": email,
                        "refreshToken": rt,
                        "accessToken": None,
                        "expiry": 0,
                        "enabled": True,
                        "cooldownUntil": 0,
                        "created_at": int(time.time())
                    }
                    replaced = False
                    for idx, a in enumerate(accs):
                        if a.get("email") == email:
                            accs[idx] = new_acc
                            replaced = True
                            break
                    if not replaced:
                        accs.append(new_acc)
                    save_accounts(accs)
                    pending_oauth.pop(session_id, None)
                    return {"status": "success", "email": email}
                else:
                    return {"status": "error", "message": f"Cline 注册失败: {reg_r.text}"}
            elif res.get("error") == "authorization_pending":
                return {"status": "pending"}
            else:
                return {"status": "pending"}
        except Exception:
            return {"status": "pending"}

@app.post("/admin/api/account/toggle")
async def admin_toggle(req: Request):
    data = await req.json()
    acc_id = data.get("id")
    accs = load_accounts()
    for a in accs:
        if a.get("id") == acc_id:
            a["enabled"] = not a.get("enabled", True)
            break
    save_accounts(accs)
    return {"ok": True}

@app.post("/admin/api/account/delete")
async def admin_delete(req: Request):
    data = await req.json()
    acc_id = data.get("id")
    accs = load_accounts()
    accs = [a for a in accs if a.get("id") != acc_id]
    save_accounts(accs)
    return {"ok": True}

def responses_to_chat_body(req_body: Dict[str, Any]) -> Dict[str, Any]:
    """将 OpenAI Responses API 请求体完整转译为标准 chat/completions"""
    chat_body: Dict[str, Any] = {
        "model": req_body.get("model", "cline-free/deepseek-v4.1-flash"),
        "stream": req_body.get("stream", False),
    }
    for k in ["temperature", "top_p", "stop", "seed", "user"]:
        if k in req_body:
            chat_body[k] = req_body[k]

    msgs = []
    # 注入 instructions 为 system 消息
    if "instructions" in req_body and req_body["instructions"]:
        msgs.append({"role": "system", "content": str(req_body["instructions"])})

    # 解析 input 树 (支持 string 或 message / function_call 对象列表)
    inp = req_body.get("input", "")
    if isinstance(inp, str):
        msgs.append({"role": "user", "content": inp})
    elif isinstance(inp, list):
        for item in inp:
            if not isinstance(item, dict):
                continue
            itype = item.get("type", "message")
            if itype == "message":
                role = item.get("role", "user")
                content = item.get("content", "")
                if isinstance(content, list):
                    txt_parts = [c.get("text", "") for c in content if isinstance(c, dict) and "text" in c]
                    content = "".join(txt_parts) if txt_parts else str(content)
                msgs.append({"role": role, "content": str(content)})
            elif itype == "function_call":
                call_id = item.get("call_id") or item.get("id") or "call_default"
                args = item.get("arguments", "{}")
                if isinstance(args, dict):
                    args = json.dumps(args)
                msgs.append({
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [{
                        "id": call_id,
                        "type": "function",
                        "function": {"name": item.get("name", "tool"), "arguments": args}
                    }]
                })
            elif itype == "function_call_output":
                call_id = item.get("call_id") or item.get("id") or "call_default"
                out = item.get("output", "")
                if isinstance(out, dict):
                    out = json.dumps(out)
                msgs.append({"role": "tool", "content": str(out), "tool_call_id": call_id})
    chat_body["messages"] = msgs

    # 转译 tools
    if "tools" in req_body and isinstance(req_body["tools"], list):
        c_tools = []
        for t in req_body["tools"]:
            if isinstance(t, dict):
                if t.get("type") == "function":
                    c_tools.append(t)
                elif "function" in t:
                    c_tools.append({"type": "function", "function": t["function"]})
                else:
                    c_tools.append({"type": "function", "function": t})
        chat_body["tools"] = c_tools
    if "tool_choice" in req_body:
        chat_body["tool_choice"] = req_body["tool_choice"]
    return chat_body

@app.post("/v1/responses")
async def openai_responses_endpoint(request: Request):
    """原生支持 Codex 桌面端 responses直通调用 (对齐 luawei1 responses.go)"""
    try:
        raw_body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    chat_body = responses_to_chat_body(raw_body)
    is_stream = chat_body.get("stream", False)

    # 包装伪造 Request 传递给成熟的 chat_completions 核心
    class MockRequest:
        def __init__(self, headers, body_json):
            self.headers = headers
            self._body = body_json
        async def json(self):
            return self._body

    mock_req = MockRequest(request.headers, chat_body)
    resp = await chat_completions(mock_req)
    # 如果是非流式响应，包装一层 responses 格式外壳
    if not is_stream and isinstance(resp, JSONResponse):
        try:
            c_data = json.loads(resp.body.decode("utf-8"))
            choice = c_data.get("choices", [{}])[0]
            msg = choice.get("message", {})
            r_output = []
            if msg.get("content"):
                r_output.append({"type": "message", "role": "assistant", "content": [{"type": "text", "text": msg["content"]}]})
            if msg.get("tool_calls"):
                for tc in msg["tool_calls"]:
                    fn = tc.get("function", {})
                    r_output.append({
                        "type": "function_call",
                        "call_id": tc.get("id"),
                        "name": fn.get("name"),
                        "arguments": fn.get("arguments", "{}")
                    })
            r_resp = {
                "id": f"resp_{uuid.uuid4().hex}",
                "object": "response",
                "created": int(time.time()),
                "model": c_data.get("model", chat_body.get("model")),
                "output": r_output,
                "usage": c_data.get("usage", {})
            }
            return JSONResponse(r_resp)
        except Exception:
            return resp
    return resp


async def sync_recommended_models_loop():
    """后台每小时动态同步 Cline 官方免 credits 推荐模型池 (对齐 models_sync.go)"""
    while True:
        try:
            await asyncio.sleep(3600)  # 每小时同步一次
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get("https://api.cline.bot/api/v1/ai/cline/recommended-models")
                if r.status_code == 200:
                    data = r.json()
                    free_models = data.get("free", [])
                    if free_models:
                        logger.info(f"Dynamic model pool refreshed: {len(free_models)} free models available")
        except Exception as e:
            logger.warning(f"Error in dynamic model sync loop: {e}")

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(sync_recommended_models_loop())


if __name__ == "__main__":
    if not os.path.exists(CONFIG_FILE):
        default_pwd = os.environ.get("ADMIN_PASSWORD", "admin123")
        default_key = os.environ.get("API_KEY", f"sk-cline-{uuid.uuid4().hex[:16]}")
        save_config({"api_key": default_key, "admin_password": default_pwd})
    if not os.path.exists(ACCOUNTS_FILE):
        save_accounts([])
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "18091"))
    uvicorn.run(app, host=host, port=port, log_level="info")


