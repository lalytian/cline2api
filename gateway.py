#!/usr/bin/env python3
"""
cline2api - 本地轻量 Cline 管理网关 (coibox OCI ARM 宿主机版)
1. 原生 Web 管理面板 (/admin)，支持：开关、删除、重登录、设备码一键发起 OAuth、手动粘贴导入 RefreshToken
2. 免费模型实时监控面板 (/admin/models) 与探活测试（与 Cline 客户端官方目录完全对齐）
3. 逆向 Cline 官方客户端协议，提供 OpenAI 兼容端点 (/v1/models, /v1/chat/completions)
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

DATA_DIR = "/opt/cline2api"
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
    return {"api_key": "sk-cline2api-secret", "admin_password": "tianli_admin"}

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

async def refresh_account_token(acc: Dict[str, Any]) -> Optional[str]:
    url = f"{CLINE_API_BASE}/auth/refresh"
    payload = {
        "refreshToken": acc["refreshToken"],
        "grantType": "refresh_token"
    }
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            res = await client.post(url, json=payload, headers={"Content-Type": "application/json"})
            if res.status_code == 200:
                data = res.json().get("data", {})
                new_at = data.get("accessToken")
                new_rt = data.get("refreshToken")
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
            else:
                acc["last_error"] = f"HTTP {res.status_code}: {res.text[:200]}"
                logger.error(f"Failed to refresh token for {acc.get('email')}: {acc['last_error']}")
        except Exception as e:
            acc["last_error"] = str(e)
            logger.error(f"Exception refreshing token for {acc.get('email')}: {e}")
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
        "User-Agent": "Cline/3.0.47",
        "HTTP-Referer": "https://cline.bot",
        "X-Title": "Cline",
        "X-IS-MULTIROOT": "false",
        "X-CLIENT-TYPE": "cline-sdk",
        "X-CLIENT-VERSION": "3.0.47",
        "X-PLATFORM": "terminal",
        "X-PLATFORM-VERSION": "3.0.47",
        "X-CORE-VERSION": "0.0.66",
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
        "id": "cline-free/kimi-k3",
        "name": "Kimi K3 (free)",
        "description": "Leading open-weights model",
        "badge": "FREE",
        "source": "official_free",
        "type": "官方免配额通道"
    },
    {
        "id": "cline-free/muse-spark-1.3-contributor",
        "name": "Muse Spark 1.3 Contributor (free)",
        "description": "Meta’s multimodal reasoning model for experimentation, learning, and early-stage agentic, multi-agent, and coding workflows.",
        "badge": "FREE",
        "source": "official_free",
        "type": "官方免配额通道"
    },
    {
        "id": "z-ai/glm-5.3-flash",
        "name": "GLM 5.3 Flash (free)",
        "description": "Latest natively multimodal model in the GLM-5 series.",
        "badge": "FREE",
        "source": "official_free",
        "type": "官方免配额通道"
    },
    {
        "id": "cline-free/solar-pro4",
        "name": "Solar Pro 4 (free)",
        "description": "Strong model for office productivity, document-intensive work, and coding.",
        "badge": "FREE",
        "source": "official_free",
        "type": "官方免配额通道"
    },
    {
        "id": "openrouter/free",
        "name": "Free Models Router",
        "description": "OpenRouter 动态免费路由通道",
        "badge": "ROUTER",
        "source": "official_free",
        "type": "动态路由通道"
    }
]

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
            
            # 追加官方 Free 通道模型
            for fm in OFFICIAL_FREE_MODELS:
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

    body.pop("max_tokens", None)
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
            client = httpx.AsyncClient(timeout=120.0)
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
                    if r.status_code == 429 or "Daily free limit reached" in err_text:
                        cd_ms = parse_cooldown_ms(err_text, r.status_code)
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
            client = httpx.AsyncClient(timeout=120.0)
            try:
                r = await client.post(upstream_url, json=stream_body, headers=headers)
                if r.status_code != 200:
                    err_text = r.text
                    if r.status_code == 429 or "Daily free limit reached" in err_text:
                        cd_ms = parse_cooldown_ms(err_text, r.status_code)
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
            <h1>Cline2API 管理控制台</h1>
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

if __name__ == "__main__":
    if not os.path.exists(CONFIG_FILE):
        save_config({"api_key": f"sk-cline-{uuid.uuid4().hex}", "admin_password": "tianli_admin"})
    if not os.path.exists(ACCOUNTS_FILE):
        save_accounts([])
    uvicorn.run(app, host="127.0.0.1", port=18091, log_level="info")
