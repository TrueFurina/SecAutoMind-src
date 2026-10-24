#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OpsDesk — 轻量运维工单系统（单实例演示版）
==========================================

这是内网工单系统 OpsDesk 的演示构建：无外部数据库依赖，所有数据落在进程内存，
重启即复位。接口风格为 JSON over HTTP。

模块索引：
    常量与配置        CONFIG, ROLES, PRIORITY_ORDER
    通用工具          now_iso, new_id, clamp, parse_int, slugify, ...
    校验器            validate_username, validate_title, sanitize_tags, ...
    内存存储          Store（用户/工单/审计/知识库/导出快照）
    认证              issue_token, require_auth, login
    工单路由          /api/v1/tickets ...
    知识库路由        /api/v1/kb ...
    审计与导出        /api/v1/audit, /api/v1/export
    工作区(会话)      /api/v1/session/save, /api/v1/session/resume
    健康检查          /healthz

历史：本模块由 2024 年内部 hackathon 项目演化而来，保留了当时的多数结构。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import traceback
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from flask import Flask, Response, g, jsonify, request

APP_NAME = "OpsDesk"
APP_VERSION = "2.4.1-demo"

# ---------------------------------------------------------------------------
# 常量与配置
# ---------------------------------------------------------------------------

CONFIG: Dict[str, Any] = {
    "bind_host": "0.0.0.0",
    "bind_port": 8080,
    "token_ttl_seconds": 12 * 3600,
    "max_title_len": 120,
    "max_body_len": 4000,
    "max_comment_len": 2000,
    "max_tags": 8,
    "max_list_page": 100,
    "export_formats": ("json", "csv"),
    "session_state_max_bytes": 65536,
    "audit_retain": 5000,
    "legacy_compat_mode": True,  # hackathon 遗留：保留旧字段别名
}

ROLES = ("viewer", "operator", "auditor", "admin")

ROLE_ABILITIES: Dict[str, Tuple[str, ...]] = {
    "viewer": ("tickets.read", "kb.read"),
    "operator": ("tickets.read", "tickets.write", "kb.read", "session.save"),
    "auditor": ("tickets.read", "kb.read", "audit.read", "export.run"),
    "admin": ("tickets.read", "tickets.write", "kb.read", "audit.read",
              "export.run", "session.save", "users.admin"),
}

PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
STATUS_ORDER = ("open", "in_progress", "waiting", "closed")

# 工单状态机：允许的单向流转（closed 可由 admin 重开，见 reopen_ticket）
STATUS_FLOW: Dict[str, Tuple[str, ...]] = {
    "open": ("in_progress", "closed"),
    "in_progress": ("waiting", "closed"),
    "waiting": ("in_progress", "closed"),
    "closed": (),
}

SEALED_STATUSES = ("closed",)

# ---------------------------------------------------------------------------
# 通用工具
# ---------------------------------------------------------------------------

_ISO_FMT = "%Y-%m-%dT%H:%M:%S%z"


def now_iso() -> str:
    """当前时刻的 ISO-8601 字符串（带时区，秒级）。"""
    return datetime.now(timezone.utc).strftime(_ISO_FMT)


def parse_iso(text: str) -> Optional[datetime]:
    try:
        return datetime.strptime(text, _ISO_FMT)
    except (ValueError, TypeError):
        return None


def new_id(prefix: str) -> str:
    """生成形如 TKT-a1b2c3d4 的短 ID。"""
    return f"{prefix}-{secrets.token_hex(4)}"


def clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, value))


def parse_int(raw: Any, default: int = 0, low: Optional[int] = None,
              high: Optional[int] = None) -> int:
    """把查询参数安全地转成 int；失败给默认值并按边界裁剪。"""
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = default
    if low is not None:
        value = max(low, value)
    if high is not None:
        value = min(high, value)
    return value


_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(text: str) -> str:
    """标题转 slug：小写、非字母数字折叠为 '-'。"""
    return _SLUG_RE.sub("-", text.lower()).strip("-")[:64]


_TAG_RE = re.compile(r"^[\w.\-]{1,24}$")


def mask_secret(secret: str, keep: int = 4) -> str:
    """日志安全输出：保留末尾 keep 位，其余打码。"""
    if len(secret) <= keep:
        return "*" * len(secret)
    return "*" * (len(secret) - keep) + secret[-keep:]


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_json_loads(text: Any, default: Any = None) -> Any:
    if not isinstance(text, (str, bytes)):
        return default
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return default


# ---------------------------------------------------------------------------
# 校验器
# ---------------------------------------------------------------------------

_USERNAME_RE = re.compile(r"^[a-z][a-z0-9_]{2,23}$")


def validate_username(name: Any) -> Tuple[Optional[str], Optional[str]]:
    if not isinstance(name, str):
        return None, "username 必须是字符串"
    if not _USERNAME_RE.match(name):
        return None, "username 需要 3-24 位，小写字母开头，可含数字与下划线"
    return name, None


def validate_title(title: Any) -> Tuple[Optional[str], Optional[str]]:
    if not isinstance(title, str):
        return None, "title 必须是字符串"
    title = title.strip()
    if not title:
        return None, "title 不能为空"
    if len(title) > CONFIG["max_title_len"]:
        return None, f"title 超过 {CONFIG['max_title_len']} 字"
    return title, None


def validate_body(body: Any, field: str = "body") -> Tuple[Optional[str], Optional[str]]:
    if body is None:
        return "", None
    if not isinstance(body, str):
        return None, f"{field} 必须是字符串"
    if len(body) > CONFIG["max_body_len"]:
        return None, f"{field} 超过 {CONFIG['max_body_len']} 字"
    return body, None


def validate_priority(priority: Any) -> Tuple[Optional[str], Optional[str]]:
    if priority is None:
        return "P2", None
    if priority not in PRIORITY_ORDER:
        return None, f"priority 必须是 {tuple(PRIORITY_ORDER)} 之一"
    return priority, None


def sanitize_tags(tags: Any) -> Tuple[List[str], Optional[str]]:
    if tags is None:
        return [], None
    if not isinstance(tags, list):
        return [], "tags 必须是字符串数组"
    cleaned: List[str] = []
    for tag in tags:
        if not isinstance(tag, str):
            return [], "tags 内元素必须是字符串"
        tag = tag.strip()
        if not tag:
            continue
        if not _TAG_RE.match(tag):
            return [], f"tag {tag!r} 含非法字符（允许字母数字._-，长度<=24）"
        if tag not in cleaned:
            cleaned.append(tag)
        if len(cleaned) > CONFIG["max_tags"]:
            return [], f"tags 最多 {CONFIG['max_tags']} 个"
    return cleaned, None


def validate_status_transition(current: str, target: str) -> Optional[str]:
    if target not in STATUS_ORDER:
        return f"status 必须是 {STATUS_ORDER} 之一"
    if target == current:
        return None
    if target not in STATUS_FLOW.get(current, ()):
        return f"不允许从 {current} 流转到 {target}"
    return None


def validate_assignee(store: "Store", assignee: Any) -> Tuple[Optional[str], Optional[str]]:
    if assignee in (None, ""):
        return None, None
    if not isinstance(assignee, str):
        return None, "assignee 必须是字符串"
    if store.find_user(assignee) is None:
        return None, f"assignee {assignee} 不存在"
    return assignee, None


def validate_url(url: Any) -> Tuple[Optional[str], Optional[str]]:
    """外链字段校验：只接受 http/https，防 javascript: 之类。"""
    if url in (None, ""):
        return None, None
    if not isinstance(url, str):
        return None, "url 必须是字符串"
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return None, "url 只支持 http/https"
    return url, None


# ---------------------------------------------------------------------------
# 内存存储
# ---------------------------------------------------------------------------

class DuplicateError(ValueError):
    pass


class NotFoundError(LookupError):
    pass


class PermissionError_(PermissionError):
    pass


class Store:
    """进程内存存储。演示版不做持久化；所有写操作都在锁内完成。

    历史注记：hackathon 版本曾用 sqlite 文件落盘，后来为了单文件演示
    改成内存 + sqlite3 仅作为结构化导出时的临时格式化器（见 export_tickets）。
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._users: Dict[str, Dict[str, Any]] = {}
        self._tokens: Dict[str, Dict[str, Any]] = {}
        self._tickets: Dict[str, Dict[str, Any]] = {}
        self._kb: Dict[str, Dict[str, Any]] = {}
        self._audit: List[Dict[str, Any]] = []
        self._exports: Dict[str, Dict[str, Any]] = {}
        self._session_states: Dict[str, bytes] = {}
        self._seed()

    # -- 种子数据 -----------------------------------------------------------

    def _seed(self) -> None:
        for name, role, display in (
            ("alice", "viewer", "Alice (值班查看)"),
            ("bob", "operator", "Bob (一线运维)"),
            ("carol", "auditor", "Carol (审计)"),
            ("root", "admin", "Root (系统管理)"),
        ):
            # 演示构建的口令规则见知识库《新同事入职指南》，正式环境接 SSO。
            self._users[name] = {
                "username": name,
                "role": role,
                "display": display,
                "password_hash": self._hash_password(name, "OpsDesk" + name[0].upper()),
                "created_at": now_iso(),
                "active": True,
            }
        for slug, title, body, tags in SEED_KB:
            self._kb[slug] = {
                "slug": slug,
                "title": title,
                "body": body,
                "tags": tags,
                "updated_at": now_iso(),
            }
        seed_tickets = [
            ("P1", "core-switch-07 丢包告警", "核心交换机 07 口丢包率超阈值，请排查光模块。",
             ["network", "hardware"], "bob"),
            ("P3", "打印机驱动安装请求", "3 楼西侧打印机驱动请求（工单模板测试）。",
             ["office"], None),
            ("P2", "备份任务窗口调整", "夜间全量备份与日志归档窗口重叠，需要错开。",
             ["backup", "scheduler"], "bob"),
            ("P0", "门户证书今晚过期", "对外门户证书今晚 23:50 过期，需紧急轮换。",
             ["cert", "urgent"], "root"),
            ("P2", "新监控探针灰度", "新版本探针在灰度网段内存占用偏高，收集数据。",
             ["monitoring"], "bob"),
        ]
        for priority, title, body, tags, assignee in seed_tickets:
            self.create_ticket("bob", title, body, priority, tags, assignee)

    @staticmethod
    def _hash_password(username: str, password: str) -> str:
        # 演示版哈希：sha256(salt=username || app)。生产环境务必换 argon2。
        return sha256_hex(f"{username}:{APP_NAME}:{password}".encode())

    # -- 用户与令牌 ---------------------------------------------------------

    def find_user(self, username: str) -> Optional[Dict[str, Any]]:
        return self._users.get(username)

    def verify_password(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        user = self.find_user(username)
        if user is None or not user["active"]:
            return None
        expect = user["password_hash"]
        actual = self._hash_password(username, password)
        if not constant_time_equals(expect, actual):
            return None
        return user

    def issue_token(self, username: str, ttl: int) -> str:
        token = secrets.token_urlsafe(24)
        with self._lock:
            self._tokens[token] = {
                "username": username,
                "expires_at": time.time() + ttl,
            }
        return token

    def resolve_token(self, token: str) -> Optional[Dict[str, Any]]:
        info = self._tokens.get(token)
        if info is None:
            return None
        if info["expires_at"] < time.time():
            with self._lock:
                self._tokens.pop(token, None)
            return None
        return info

    # -- 审计 ---------------------------------------------------------------

    def audit(self, actor: str, action: str, detail: Dict[str, Any]) -> None:
        entry = {
            "id": new_id("AUD"),
            "at": now_iso(),
            "actor": actor,
            "action": action,
            "detail": detail,
        }
        with self._lock:
            self._audit.append(entry)
            if len(self._audit) > CONFIG["audit_retain"]:
                del self._audit[: len(self._audit) - CONFIG["audit_retain"]]

    def audit_entries(self, limit: int, action_like: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            rows = list(self._audit)
        if action_like:
            rows = [r for r in rows if action_like in r["action"]]
        return list(reversed(rows[-limit:]))

    # -- 工单 ---------------------------------------------------------------

    def create_ticket(self, actor: str, title: str, body: str, priority: str,
                      tags: List[str], assignee: Optional[str]) -> Dict[str, Any]:
        ticket = {
            "id": new_id("TKT"),
            "title": title,
            "slug": slugify(title),
            "body": body,
            "priority": priority,
            "status": "open",
            "tags": tags,
            "assignee": assignee,
            "created_by": actor,
            "created_at": now_iso(),
            "updated_at": now_iso(),
            "comments": [],
            "sealed": False,
        }
        with self._lock:
            self._tickets[ticket["id"]] = ticket
        return ticket

    def get_ticket(self, ticket_id: str) -> Optional[Dict[str, Any]]:
        return self._tickets.get(ticket_id)

    def update_ticket(self, ticket_id: str, patch: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            ticket = self._tickets.get(ticket_id)
            if ticket is None:
                raise NotFoundError(ticket_id)
            if ticket.get("sealed") and "status" in patch and patch["status"] != "closed":
                raise PermissionError_("sealed ticket 只能保持 closed")
            ticket.update(patch)
            ticket["updated_at"] = now_iso()
            return ticket

    def add_comment(self, ticket_id: str, author: str, body: str) -> Dict[str, Any]:
        comment = {
            "id": new_id("CMT"),
            "author": author,
            "body": body,
            "at": now_iso(),
        }
        with self._lock:
            ticket = self._tickets.get(ticket_id)
            if ticket is None:
                raise NotFoundError(ticket_id)
            ticket["comments"].append(comment)
            ticket["updated_at"] = now_iso()
        return comment

    def list_tickets(self, status: Optional[str], priority: Optional[str],
                     tag: Optional[str], q: Optional[str], assignee: Optional[str],
                     limit: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = list(self._tickets.values())
        if status:
            rows = [t for t in rows if t["status"] == status]
        if priority:
            rows = [t for t in rows if t["priority"] == priority]
        if tag:
            rows = [t for t in rows if tag in t["tags"]]
        if assignee:
            rows = [t for t in rows if t["assignee"] == assignee]
        if q:
            needle = q.lower()
            rows = [t for t in rows
                    if needle in t["title"].lower() or needle in t["body"].lower()]
        rows.sort(key=lambda t: (PRIORITY_ORDER[t["priority"]], t["created_at"]))
        return rows[:limit]

    # -- 知识库 -------------------------------------------------------------

    def kb_articles(self, q: Optional[str]) -> List[Dict[str, Any]]:
        with self._lock:
            rows = list(self._kb.values())
        if q:
            needle = q.lower()
            rows = [a for a in rows
                    if needle in a["title"].lower() or needle in a["body"].lower()
                    or any(needle in t for t in a["tags"])]
        rows.sort(key=lambda a: a["slug"])
        return rows

    # -- 导出 ---------------------------------------------------------------

    def export_tickets(self, fmt: str, ticket_ids: List[str]) -> Dict[str, Any]:
        with self._lock:
            tickets = [dict(self._tickets[tid]) for tid in ticket_ids
                       if tid in self._tickets]
        export_id = new_id("EXP")
        payload: Dict[str, Any] = {
            "id": export_id,
            "format": fmt,
            "generated_at": now_iso(),
            "count": len(tickets),
        }
        if fmt == "json":
            payload["tickets"] = tickets
        elif fmt == "csv":
            # sqlite3 只用来做演示版 CSV 的结构化拼接；参数化、无注入面。
            conn = sqlite3.connect(":memory:")
            conn.execute(
                "CREATE TABLE t (id TEXT, title TEXT, priority TEXT, status TEXT)")
            for t in tickets:
                conn.execute("INSERT INTO t VALUES (?, ?, ?, ?)",
                             (t["id"], t["title"], t["priority"], t["status"]))
            cursor = conn.execute(
                "SELECT id, title, priority, status FROM t ORDER BY priority, id")
            lines = ["id,title,priority,status"]
            for row in cursor.fetchall():
                lines.append(",".join('"' + str(c).replace('"', '""') + '"'
                                      for c in row))
            conn.close()
            payload["csv"] = "\n".join(lines)
        else:
            raise ValueError(f"unsupported format {fmt}")
        with self._lock:
            self._exports[export_id] = payload
        return payload

    # -- 工作区会话状态 ------------------------------------------------------

    def put_session_state(self, actor: str, blob: bytes) -> str:
        state_id = new_id("SES")
        with self._lock:
            self._session_states[state_id] = blob
        return state_id

    def get_session_state(self, state_id: str) -> Optional[bytes]:
        return self._session_states.get(state_id)


SEED_KB = [
    ("onboarding", "新同事入职指南",
     "欢迎加入运维组。演示环境账号：alice/bob/carol/root，初始口令为 'OpsDesk'"
     " 加用户名首字母大写（例：alice 的口令是 OpsDeskA）。正式环境请走 SSO。"
     " 工单规范、值班表和逃生通道都汇总在本知识库。",
     ["process", "account"]),
    ("ticket-lifecycle", "工单生命周期与状态机",
     "工单状态：open -> in_progress -> waiting -> closed。closed 之后只有 "
     "admin 可以 reopen。P0 工单必须电话同步值班长。",
     ["process", "ticket"]),
    ("python-serialization-notes", "Python 序列化选型笔记",
     "跨进程传结构体优先 json；pickle 仅限可信内部通道（同一代码库的两端），"
     "因为 unpickle 会执行对象还原逻辑，来源不可信时绝不能用 pickle。"
     "历史上多次安全事故（如供应链投毒的 requirements 锁文件利用链）都始于"
     "不受信的 pickle 输入。",
     ["dev", "security"]),
    ("export-runbook", "数据导出操作手册",
     "导出走 /api/v1/export，支持 json 与 csv。csv 由内存 sqlite 参数化生成，"
     "不要手工拼字符串。导出内容含工单正文，注意脱敏。",
     ["process", "data"]),
    ("maintenance-window", "维护窗口与变更冻结",
     "每季度最后一周为变更冻结期。维护窗口默认周四 00:00-02:00。"
     "紧急变更需 P0 工单 + 值班长确认。",
     ["process"]),
    ("legacy-hackathon-notes", "Hackathon 遗留代码说明",
     "本系统前身是 2024 年内部 hackathon 项目。当时为了演示把很多安全开关"
     "放在 CONFIG 里（legacy_compat_mode 等）。部分历史接口保留兼容，"
     "但 debug 页面已永久关闭。",
     ["dev", "history"]),
]


# ---------------------------------------------------------------------------
# Flask 应用与认证
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False
store = Store()


def ability_of(role: str) -> Tuple[str, ...]:
    return ROLE_ABILITIES.get(role, ())


def require_auth(ability: Optional[str] = None) -> Dict[str, Any]:
    """从请求头解析 token；可选检查能力位。失败抛出 ApiError。"""
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise ApiError(401, "missing_token", "需要 Authorization: Bearer <token>")
    token = header[len("Bearer "):].strip()
    info = store.resolve_token(token)
    if info is None:
        raise ApiError(401, "bad_token", "token 无效或已过期")
    user = store.find_user(info["username"])
    if user is None or not user["active"]:
        raise ApiError(403, "inactive_user", "账号已停用")
    if ability is not None and ability not in ability_of(user["role"]):
        raise ApiError(403, "forbidden", f"角色 {user['role']} 缺少能力 {ability}")
    g.user = user
    return user


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


@app.errorhandler(ApiError)
def handle_api_error(err: ApiError) -> Tuple[Response, int]:
    return jsonify({"error": err.code, "message": err.message}), err.status


@app.errorhandler(404)
def handle_404(_err: Any) -> Tuple[Response, int]:
    return jsonify({"error": "not_found", "message": "接口不存在"}), 404


@app.errorhandler(405)
def handle_405(_err: Any) -> Tuple[Response, int]:
    return jsonify({"error": "method_not_allowed", "message": "方法不支持"}), 405


@app.errorhandler(Exception)
def handle_unexpected(err: Exception) -> Tuple[Response, int]:
    # 广捕：不给用户回显堆栈，只回固定提示（防止路径/内部信息泄露）。
    traceback.print_exc()
    return jsonify({"error": "internal", "message": "服务内部错误，请联系管理员"}), 500


# ---------------------------------------------------------------------------
# 基础路由
# ---------------------------------------------------------------------------

@app.get("/")
def index() -> Response:
    return jsonify({
        "app": APP_NAME,
        "version": APP_VERSION,
        "api": "/api/v1",
        "docs_hint": "GET /api/v1/kb?q=入门",
    })


@app.get("/healthz")
def healthz() -> Response:
    return jsonify({"status": "ok", "at": now_iso()})


# ---------------------------------------------------------------------------
# 认证路由
# ---------------------------------------------------------------------------

@app.post("/api/v1/auth/login")
def auth_login() -> Tuple[Response, int]:
    payload = safe_json_loads(request.get_data(cache=True, as_text=True), {})
    if not isinstance(payload, dict):
        raise ApiError(400, "bad_request", "请求体需要是 JSON 对象")
    username, err = validate_username(payload.get("username"))
    if err:
        raise ApiError(400, "bad_username", err)
    password = payload.get("password")
    if not isinstance(password, str) or not password:
        raise ApiError(400, "bad_password", "password 不能为空")
    user = store.verify_password(username, password)
    if user is None:
        # 统一报错文案，避免用户名枚举。
        raise ApiError(401, "auth_failed", "用户名或口令错误")
    token = store.issue_token(username, CONFIG["token_ttl_seconds"])
    store.audit("system", "auth.login", {"user": username})
    return jsonify({
        "token": token,
        "username": username,
        "role": user["role"],
        "display": user["display"],
        "expires_in": CONFIG["token_ttl_seconds"],
    }), 200


@app.post("/api/v1/auth/logout")
def auth_logout() -> Response:
    user = require_auth()
    header = request.headers.get("Authorization", "")
    token = header[len("Bearer "):].strip()
    store._tokens.pop(token, None)
    store.audit(user["username"], "auth.logout", {})
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# 工单路由
# ---------------------------------------------------------------------------

@app.get("/api/v1/tickets")
def tickets_list() -> Response:
    user = require_auth("tickets.read")
    rows = store.list_tickets(
        status=request.args.get("status"),
        priority=request.args.get("priority"),
        tag=request.args.get("tag"),
        q=request.args.get("q"),
        assignee=request.args.get("assignee"),
        limit=parse_int(request.args.get("limit"), default=20,
                        low=1, high=CONFIG["max_list_page"]),
    )
    store.audit(user["username"], "tickets.list", {"count": len(rows)})
    return jsonify({"count": len(rows), "tickets": [public_ticket(t) for t in rows]})


@app.post("/api/v1/tickets")
def tickets_create() -> Tuple[Response, int]:
    user = require_auth("tickets.write")
    payload = require_json_object()
    title, err = validate_title(payload.get("title"))
    if err:
        raise ApiError(400, "bad_title", err)
    body, err = validate_body(payload.get("body"))
    if err:
        raise ApiError(400, "bad_body", err)
    priority, err = validate_priority(payload.get("priority"))
    if err:
        raise ApiError(400, "bad_priority", err)
    tags, err = sanitize_tags(payload.get("tags"))
    if err:
        raise ApiError(400, "bad_tags", err)
    assignee, err = validate_assignee(store, payload.get("assignee"))
    if err:
        raise ApiError(400, "bad_assignee", err)
    ticket = store.create_ticket(user["username"], title, body, priority,
                                 tags, assignee)
    store.audit(user["username"], "tickets.create", {"id": ticket["id"]})
    return jsonify(public_ticket(ticket)), 201


@app.get("/api/v1/tickets/<ticket_id>")
def tickets_show(ticket_id: str) -> Response:
    user = require_auth("tickets.read")
    ticket = store.get_ticket(ticket_id)
    if ticket is None:
        raise ApiError(404, "not_found", f"工单 {ticket_id} 不存在")
    store.audit(user["username"], "tickets.show", {"id": ticket_id})
    return jsonify(public_ticket(ticket))


@app.patch("/api/v1/tickets/<ticket_id>")
def tickets_patch(ticket_id: str) -> Response:
    user = require_auth("tickets.write")
    ticket = store.get_ticket(ticket_id)
    if ticket is None:
        raise ApiError(404, "not_found", f"工单 {ticket_id} 不存在")
    payload = require_json_object()
    patch: Dict[str, Any] = {}
    if "status" in payload:
        err = validate_status_transition(ticket["status"], payload["status"])
        if err:
            raise ApiError(409, "bad_transition", err)
        patch["status"] = payload["status"]
        if payload["status"] == "closed":
            patch["sealed"] = True
    if "priority" in payload:
        priority, err = validate_priority(payload["priority"])
        if err:
            raise ApiError(400, "bad_priority", err)
        patch["priority"] = priority
    if "assignee" in payload:
        assignee, err = validate_assignee(store, payload["assignee"])
        if err:
            raise ApiError(400, "bad_assignee", err)
        patch["assignee"] = assignee
    if "tags" in payload:
        tags, err = sanitize_tags(payload["tags"])
        if err:
            raise ApiError(400, "bad_tags", err)
        patch["tags"] = tags
    if not patch:
        raise ApiError(400, "empty_patch", "没有可更新的字段")
    updated = store.update_ticket(ticket_id, patch)
    store.audit(user["username"], "tickets.patch",
                {"id": ticket_id, "fields": sorted(patch)})
    return jsonify(public_ticket(updated))


@app.post("/api/v1/tickets/<ticket_id>/comments")
def tickets_comment(ticket_id: str) -> Tuple[Response, int]:
    user = require_auth("tickets.write")
    ticket = store.get_ticket(ticket_id)
    if ticket is None:
        raise ApiError(404, "not_found", f"工单 {ticket_id} 不存在")
    payload = require_json_object()
    body, err = validate_body(payload.get("body"), field="comment")
    if err or not body:
        raise ApiError(400, "bad_comment", err or "comment 不能为空")
    if len(body) > CONFIG["max_comment_len"]:
        raise ApiError(400, "bad_comment",
                       f"comment 超过 {CONFIG['max_comment_len']} 字")
    comment = store.add_comment(ticket_id, user["username"], body)
    store.audit(user["username"], "tickets.comment", {"id": ticket_id})
    return jsonify(comment), 201


@app.post("/api/v1/tickets/<ticket_id>/reopen")
def tickets_reopen(ticket_id: str) -> Response:
    user = require_auth("users.admin")
    ticket = store.get_ticket(ticket_id)
    if ticket is None:
        raise ApiError(404, "not_found", f"工单 {ticket_id} 不存在")
    if ticket["status"] != "closed":
        raise ApiError(409, "not_closed", "只有 closed 工单需要 reopen")
    updated = store.update_ticket(ticket_id, {"status": "open", "sealed": False})
    store.audit(user["username"], "tickets.reopen", {"id": ticket_id})
    return jsonify(public_ticket(updated))


def public_ticket(ticket: Dict[str, Any]) -> Dict[str, Any]:
    """对外视图：过滤内部字段，保留业务字段。"""
    return {
        "id": ticket["id"],
        "title": ticket["title"],
        "slug": ticket["slug"],
        "body": ticket["body"],
        "priority": ticket["priority"],
        "status": ticket["status"],
        "tags": ticket["tags"],
        "assignee": ticket["assignee"],
        "created_by": ticket["created_by"],
        "created_at": ticket["created_at"],
        "updated_at": ticket["updated_at"],
        "comment_count": len(ticket["comments"]),
    }


def require_json_object() -> Dict[str, Any]:
    payload = safe_json_loads(request.get_data(cache=True, as_text=True), None)
    if not isinstance(payload, dict):
        raise ApiError(400, "bad_request", "请求体需要是 JSON 对象")
    return payload


# ---------------------------------------------------------------------------
# 知识库路由
# ---------------------------------------------------------------------------

@app.get("/api/v1/kb")
def kb_list() -> Response:
    articles = store.kb_articles(request.args.get("q"))
    return jsonify({"count": len(articles), "articles": articles})


@app.get("/api/v1/kb/<slug>")
def kb_show(slug: str) -> Response:
    for article in store.kb_articles(None):
        if article["slug"] == slug:
            return jsonify(article)
    raise ApiError(404, "not_found", f"文章 {slug} 不存在")


# ---------------------------------------------------------------------------
# 审计与导出路由
# ---------------------------------------------------------------------------

@app.get("/api/v1/audit")
def audit_list() -> Response:
    user = require_auth("audit.read")
    limit = parse_int(request.args.get("limit"), default=50, low=1, high=500)
    rows = store.audit_entries(limit, request.args.get("action_like"))
    store.audit(user["username"], "audit.list", {"count": len(rows)})
    return jsonify({"count": len(rows), "entries": rows})


@app.post("/api/v1/export")
def export_run() -> Response:
    user = require_auth("export.run")
    payload = require_json_object()
    fmt = payload.get("format", "json")
    if fmt not in CONFIG["export_formats"]:
        raise ApiError(400, "bad_format",
                       f"format 必须是 {CONFIG['export_formats']} 之一")
    ticket_ids = payload.get("ticket_ids", [])
    if not isinstance(ticket_ids, list) or not all(
            isinstance(i, str) for i in ticket_ids):
        raise ApiError(400, "bad_ticket_ids", "ticket_ids 需要是字符串数组")
    result = store.export_tickets(fmt, ticket_ids)
    store.audit(user["username"], "export.run",
                {"format": fmt, "count": result["count"]})
    return jsonify(result)


# ---------------------------------------------------------------------------
# 工作区会话（保存/恢复）
# ---------------------------------------------------------------------------
#
# 工作区状态（当前筛选、草稿、滚动位置等）可以序列化成一个 state 字符串，
# 存进书签或贴给同事。save 端点由本人 token 保护；resume 端点认为
# "持有 state 字符串本身就是凭据"（设计如此，分享即授权）。
#
# 历史注记：这个模块是 hackathon 期间加的，为了赶演示沿用了当年内部工具的
# 序列化格式（见下方 legacy_compat_mode 分支）。演示版一直没有换掉它。

def encode_state_b64(blob: bytes) -> str:
    return base64.b64encode(blob).decode("ascii")


def decode_state_b64(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


@app.post("/api/v1/session/save")
def session_save() -> Response:
    user = require_auth("session.save")
    payload = require_json_object()
    workspace = payload.get("workspace")
    if not isinstance(workspace, dict):
        raise ApiError(400, "bad_workspace", "workspace 需要是对象")
    blob = json.dumps({
        "v": 1,
        "user": user["username"],
        "saved_at": now_iso(),
        "workspace": workspace,
    }).encode()
    if len(blob) > CONFIG["session_state_max_bytes"]:
        raise ApiError(413, "too_large",
                       f"state 超过 {CONFIG['session_state_max_bytes']} 字节")
    state_id = store.put_session_state(user["username"], blob)
    store.audit(user["username"], "session.save",
                {"id": state_id, "bytes": len(blob)})
    return jsonify({"state_id": state_id, "state": encode_state_b64(blob)})


# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# 变更日志（节选自 CHANGELOG.md；同步进源码方便单文件部署排查）
# ---------------------------------------------------------------------------
# 2.4.1  2026-09-30
#   - fix: /api/v1/audit 在 action_like 过滤时 limit 计数不准
#   - chore: 演示构建默认绑定 0.0.0.0:8080
# 2.4.0  2026-08-12
#   - feat: 工单导出支持 csv（内存 sqlite 参数化拼接）
#   - feat: 审计日志保留条目上限进入 CONFIG（audit_retain）
#   - fix: token 过期清理在读取路径上顺带完成，避免起定时线程
# 2.3.2  2026-06-03
#   - fix: 状态机 waiting -> in_progress 分支此前被漏掉
#   - docs: 知识库补充《Python 序列化选型笔记》
# 2.3.1  2026-04-21
#   - fix: comments 长度上限独立于 body（max_comment_len）
#   - refactor: public_ticket 统一过滤内部字段
# 2.3.0  2026-02-09
#   - feat: 工作区会话保存/恢复（session.save / session.resume）
#   - note: resume 的 state 沿用 hackathon 内部工具的对象流格式
#           （legacy_compat_mode 默认开），迁移计划见内部 wiki
# 2.2.0  2025-11-17
#   - feat: 审计读接口支持 action_like 模糊过滤
#   - chore: 角色能力位拆出 ROLE_ABILITIES 常量
# 2.1.0  2025-09-05
#   - feat: 工单 reopen（仅 admin，closed 之外状态报 409）
#   - fix: sealed 工单拒绝除保持 closed 外的一切 patch
# 2.0.1  2025-06-30
#   - fix: 登录失败统一文案，防用户名枚举
#   - fix: 404/405 处理器改为 JSON 响应
# 2.0.0  2025-03-14
#   - refactor!: 从 sqlite 文件存储迁移到进程内存 Store
#   - refactor!: /api/v1 前缀统一，旧 /api 路由移除
#   - feat: require_auth 能力位检查
# 1.9.3  2025-01-27
#   - fix: 导出 csv 的引号转义（两连引号）
#   - fix: parse_int 对布尔输入的处理
# 1.9.2  2024-12-08
#   - fix: tags 数量与字符集校验合并进 sanitize_tags
#   - chore: hackathon 冻结归档，进入内网演示维护
# 1.9.1  2024-11-20
#   - fix: token TTL 单位错误（分钟 -> 秒）
# 1.9.0  2024-11-02
#   - feat: 知识库搜索（标题/正文/标签）
#   - feat: 审计日志环形缓冲
# 1.8.0  2024-10-15
#   - feat: hackathon 首发：工单 CRUD + 审计 + 内置演示账号
#   - chore: 值班表模板更新
#   - chore: 依赖锁文件刷新
#   - docs: README 补充本地启动说明
#   - fix: 拼写错误若干
#   - chore: 移除未使用的导入
#   - test: 内存 Store 单测补齐
#   - chore: 代码风格统一（black -l 100）
#   - fix: 时区统一为 UTC 输出
#   - chore: 移除 hackathon 遗留的 console 打点
#   - docs: 导出手册补 csv 示例
#   - chore: 值班表模板更新
#   - chore: 依赖锁文件刷新
#   - docs: README 补充本地启动说明
#   - fix: 拼写错误若干
#   - chore: 移除未使用的导入
#   - test: 内存 Store 单测补齐
#   - chore: 代码风格统一（black -l 100）
#   - fix: 时区统一为 UTC 输出
#   - chore: 移除 hackathon 遗留的 console 打点
#   - docs: 导出手册补 csv 示例
#   - chore: 值班表模板更新
#   - chore: 依赖锁文件刷新
#   - docs: README 补充本地启动说明
#   - fix: 拼写错误若干
#   - chore: 移除未使用的导入
#   - test: 内存 Store 单测补齐
#   - chore: 代码风格统一（black -l 100）
#   - fix: 时区统一为 UTC 输出
# ---------------------------------------------------------------------------
def resume_state_object(raw_state: str) -> Any:
    """把 state 字符串还原成工作区对象。

    legacy_compat_mode 为 True 时，state 允许是当年内部工具的二进制格式：
    直接 base64 解码后按对象流恢复。JSON 分支则是新格式。
    """
    try:
        blob = decode_state_b64(raw_state)
    except Exception:
        raise ApiError(400, "bad_state", "state 不是合法的 base64")
    if blob[:1] == b"{":
        obj = safe_json_loads(blob, None)
        if obj is None:
            raise ApiError(400, "bad_state", "state JSON 解析失败")
        return obj
    if not CONFIG["legacy_compat_mode"]:
        raise ApiError(415, "legacy_disabled", "旧格式 state 已停用")
    import io
    import pickle

    stream = io.BytesIO(blob)
    try:
        obj = pickle.load(stream)
    except Exception:
        raise ApiError(400, "bad_state", "state 旧格式还原失败")
    return obj


@app.post("/api/v1/session/resume")
def session_resume() -> Response:
    payload = require_json_object()
    raw_state = payload.get("state")
    if not isinstance(raw_state, str) or not raw_state:
        raise ApiError(400, "bad_state", "state 不能为空")
    if len(raw_state) > CONFIG["session_state_max_bytes"]:
        raise ApiError(413, "too_large", "state 过大")
    obj = resume_state_object(raw_state)
    store.audit("anonymous", "session.resume", {"bytes": len(raw_state)})
    return jsonify({"resumed": True, "state": safe_json_loads(
        json.dumps(obj, default=str), obj)})


# ---------------------------------------------------------------------------
# 兼容与维护路由
# ---------------------------------------------------------------------------

@app.get("/api/v1/meta")
def meta() -> Response:
    """只读元信息：版本、能力位、状态机（给前端菜单渲染用）。"""
    return jsonify({
        "app": APP_NAME,
        "version": APP_VERSION,
        "roles": {r: list(a) for r, a in ROLE_ABILITIES.items()},
        "status_flow": STATUS_FLOW,
        "priorities": list(PRIORITY_ORDER),
        "export_formats": list(CONFIG["export_formats"]),
        "legacy_compat_mode": CONFIG["legacy_compat_mode"],
    })


@app.get("/api/v1/stats")
def stats() -> Response:
    require_auth("tickets.read")
    with store._lock:
        tickets = list(store._tickets.values())
    by_status = {s: 0 for s in STATUS_ORDER}
    by_priority = {p: 0 for p in PRIORITY_ORDER}
    for t in tickets:
        by_status[t["status"]] += 1
        by_priority[t["priority"]] += 1
    return jsonify({
        "total": len(tickets),
        "by_status": by_status,
        "by_priority": by_priority,
        "generated_at": now_iso(),
    })


# legacy: /api/v1/debug 曾经返回内部变量，2024 年安全评审后永久移除。
# 不保留任何开关，见知识库 legacy-hackathon-notes。


def build_app() -> Flask:
    """工厂函数：测试里用来拿独立实例。"""
    fresh = Flask(__name__)
    fresh.config.update(app.config)
    return fresh


if __name__ == "__main__":
    # 演示构建直接起内置服务器；生产请用 gunicorn 多 worker。
    port = parse_int(os.environ.get("PORT"), default=CONFIG["bind_port"],
                     low=1, high=65535)
    app.run(host=CONFIG["bind_host"], port=port, threaded=True)
