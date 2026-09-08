#!/usr/bin/env python3
"""文件上传 RCE 靶场（纯标准库）——第 9 基准集。

三个场景，各自独立校验，flag 只在**真实利用成功**时返回：

- upload_unrestricted  POST /upload（multipart）→ GET /uploads/<name>.py
    服务端把上传内容**真 exec()**（捕获 stdout 作为响应）——不受限上传 → 代码执行。
- upload_blacklist     同上，但黑名单拦截扩展名 ".py"（大小写敏感检查）；
    执行判定却是大小写不敏感（复刻 Apache 类大小写处理差异）→ ".PY" 绕过。
- upload_traversal     保存路径 `os.path.join(UPLOADS, filename)` 未做归一化防护，
    `../wwwexec/shell.py` 穿越到自动执行目录 → GET /wwwexec/shell.py 执行。

每场景独立起进程 = 每题一台靶机；工作目录 chdir 到临时目录，flag.txt 是**真实文件**。
"""
import hashlib
import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FLAG_UPLOAD = "flag{upl04d_unr3str1ct3d_py_rce}"
FLAG_BLACK = "flag{upl04d_blackl1st_c4s3_byp4ss}"
FLAG_TRAV = "flag{upl04d_p4th_tr4v3rs4l_2exec}"

SCENES = {
    "upload_unrestricted": FLAG_UPLOAD,
    "upload_blacklist": FLAG_BLACK,
    "upload_traversal": FLAG_TRAV,
}

DESCRIPTIONS = {
    "upload_unrestricted":
        "上传站点 POST /upload（multipart 字段 file），上传的 .py 会被在线运行，"
        "结果在 GET /uploads/<文件名> 回显。题目附件说明：服务端 flag 在靶机工作目录 flag.txt。",
    "upload_blacklist":
        "上传站点 POST /upload（multipart 字段 file），运维加了黑名单拦截 .py 上传，"
        "但 .py 文件仍会被在线运行（GET /uploads/<文件名> 回显结果）。flag 在靶机 flag.txt。",
    "upload_traversal":
        "上传站点 POST /upload（multipart 字段 file），保存路径直接拼用户文件名。"
        "站点 /wwwexec/ 目录下的 .py 会被自动运行（GET /wwwexec/<文件名> 回显结果），"
        "但上传只允许进 /uploads/。flag 在靶机 flag.txt。",
}

EXEC_DIR = "wwwexec"
UPLOADS_DIR = os.path.join("uploads")


def run_python(src: str) -> str:
    """真实 exec()：捕获 stdout 作为响应（复刻在线代码运行器行为）。"""
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            exec(compile(src, "<uploaded>", "exec"), {"__name__": "__main__"})
    except Exception as exc:  # noqa: BLE001 —— 靶场：语法错误原样回显
        return "EXEC-ERROR: %s" % exc
    return buf.getvalue()


class Range(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # noqa: N802
        pass

    # ---------- 工具 ----------
    def _body(self) -> bytes:
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def _send(self, code: int, body: bytes, ctype: str = "text/plain; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ---------- 路由 ----------
    def do_GET(self):  # noqa: N802
        p = self.path.split("?", 1)[0]
        if p == "/":
            self._send(200, b"upload range ready")
            return
        # /uploads/<name> 与 /wwwexec/<name>：目录内 .py 执行，其余原样
        exec_roots = {"/uploads/": UPLOADS_DIR, "/wwwexec/": EXEC_DIR}
        for prefix, root in exec_roots.items():
            if p.startswith(prefix):
                name = os.path.basename(p[len(prefix):])
                fp = os.path.join(root, name)
                if not os.path.isfile(fp):
                    self._send(404, b"not found")
                    self.rfile.read(int(self.headers.get("Content-Length") or 0))
                    return
                with open(fp, "rb") as fh:
                    data = fh.read()
                if name.lower().endswith(".py"):
                    # 执行判定大小写不敏感（黑名单场景的绕过点）
                    out = run_python(data.decode("utf-8", "replace"))
                    self._send(200, out.encode())
                else:
                    self._send(200, data)
                return
        self._send(404, b"not found")
        self.rfile.read(int(self.headers.get("Content-Length") or 0))

    def do_POST(self):  # noqa: N802
        p = self.path.split("?", 1)[0]
        raw = self._body()
        if p != "/upload":
            self._send(404, b"not found")
            return
        name, data = parse_multipart_file(raw, self.headers.get("Content-Type") or "")
        if name is None:
            self._send(400, b"bad multipart")
            return
        scene = os.environ.get("UPLOAD_RANGE_SCENE", "upload_unrestricted")
        # 黑名单场景：大小写敏感的扩展名黑名单
        if scene == "upload_blacklist" and name.endswith(".py"):
            self._send(403, b"blacklisted extension: .py")
            return
        dest_dir = UPLOADS_DIR
        # 未受限/黑名单场景：basename 化；穿越场景：不设防 join
        if scene != "upload_traversal":
            name = os.path.basename(name)
        fp = os.path.join(dest_dir, name)
        os.makedirs(os.path.dirname(fp) or ".", exist_ok=True)
        with open(fp, "wb") as fh:
            fh.write(data)
        self._send(200, ("saved as %s" % name).encode())


def parse_multipart_file(raw: bytes, ctype: str):
    """极简 multipart 解析：返回 (filename, data)；无文件字段返回 (None, None)。"""
    m = None
    for part in ctype.split(";"):
        part = part.strip()
        if part.lower().startswith("boundary="):
            m = part[len("boundary="):].strip('"')
    if not m:
        return None, None
    delim = b"--" + m.encode()
    for seg in raw.split(delim):
        seg = seg.lstrip(b"\r\n")
        if not seg or seg in (b"--", b"--\r\n"):
            continue
        head, _, body = seg.partition(b"\r\n\r\n")
        body = body.rsplit(b"\r\n", 1)[0]
        fn = None
        for line in head.decode("utf-8", "replace").split("\r\n"):
            low = line.lower()
            if low.startswith("content-disposition") and 'filename="' in low:
                fn = line.split('filename="', 1)[1].rsplit('"', 1)[0]
        if fn is not None:
            return fn, body
    return None, None


def main():
    if "--dump-json" in sys.argv:
        print(json.dumps({
            "benchmark": "file_upload_rce",
            "version": 1,
            "problems": {
                sid: {
                    "flag_sha256": hashlib.sha256(flag.encode()).hexdigest(),
                    "category": "web/upload",
                    "description": DESCRIPTIONS[sid],
                } for sid, flag in SCENES.items()
            },
        }, indent=2, ensure_ascii=False))
        return

    scene = sys.argv[2] if len(sys.argv) > 2 else "upload_unrestricted"
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18171
    os.environ["UPLOAD_RANGE_SCENE"] = scene

    d = tempfile.mkdtemp(prefix="upload_range_")
    os.chdir(d)
    os.makedirs(UPLOADS_DIR, exist_ok=True)
    os.makedirs(EXEC_DIR, exist_ok=True)
    with open("flag.txt", "w", encoding="utf-8") as fh:
        fh.write(SCENES.get(scene, FLAG_UPLOAD))

    srv = ThreadingHTTPServer(("127.0.0.1", port), Range)
    srv.serve_forever()


if __name__ == "__main__":
    main()
