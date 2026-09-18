#!/usr/bin/env python3
"""模拟锐捷 eportal 认证服务端，用于端到端自检。

用法: mock_ac.py <port> <expect_pwd> <logfile> <keyfile> [noredirect]

noredirect: 关闭 /eportal/redirectortosuccess.jsp 的 302 路由。
            测"拼接回退"时用，否则服务端要回会抢在拼接前面成功。

它按真实协议的形状响应：
  GET  /probe                           -> 200 劫持页（内含 location.href='...' 跳转）
  POST .../InterFace.do?method=pageInfo -> 下发 RSA 公钥 + 运营商 option 列表
  POST .../InterFace.do?method=login    -> 用私钥解密收到的 password，校验是否等于 "密码>mac"
  POST .../InterFace.do?method=logout   -> 返回注销成功
每次 login/logout 都会把过程写入 logfile，自检脚本据此判断。
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from cryptography.hazmat.primitives.asymmetric import rsa

PORT = int(sys.argv[1])
EXPECT_PWD = sys.argv[2]
LOGFILE = sys.argv[3]
KEYFILE = sys.argv[4]

MAC = "4f3839eba7a850e699faecafa73feb81"  # 与 check.sh 中劫持页里的一致
CHUNK = 126  # 客户端每块 126 字节
REDIRECT_ENABLED = "noredirect" not in sys.argv[5:]  # 见用法第 5 参

KEY = rsa.generate_private_key(public_exponent=65537, key_size=1024)
NUM = KEY.private_numbers()
N, E, D = NUM.public_numbers.n, NUM.public_numbers.e, NUM.d
WIDTH = (N.bit_length() + 3) // 4  # 模数十六进制宽度（1024bit -> 256）

with open(KEYFILE, "w") as f:
    f.write("%x\n%x\n" % (N, E))

LOG = {"requests": [], "counts": {"pageinfo": 0, "login": 0, "logout": 0, "getservices": 0, "redirect": 0}}


def decrypt_pwd(hexstr):
    """按‘右侧对齐、每 WIDTH 个十六进制字符一块’解密，还原明文。"""
    s = hexstr
    if len(s) % WIDTH:
        s = "0" * (WIDTH - len(s) % WIDTH) + s
    raw = b""
    for i in range(0, len(s), WIDTH):
        m = int(s[i:i + WIDTH], 16)
        if m >= N:
            return None, "块数值 >= n"
        raw += pow(m, D, N).to_bytes(CHUNK, "big")
    blocks = [raw[i:i + CHUNK] for i in range(0, len(raw), CHUNK)]
    plain = b"".join(reversed(blocks)).lstrip(b"\x00")
    try:
        return plain.decode("utf-8"), None
    except UnicodeDecodeError as exc:
        return None, "utf-8 解码失败: %s" % exc


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body, ctype="application/json; charset=UTF-8", code=200):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _dump(self):
        with open(LOGFILE, "w") as f:
            json.dump(LOG, f, ensure_ascii=False, indent=2)

    def do_GET(self):
        if self.path == "/probe":
            LOG["probe"] = {"path": self.path}
            self._send(
                "<html><script>location.href='http://127.0.0.1:%d/eportal/index.jsp?"
                "wlanuserip=192.168.1.100&wlanacname=AC-Test&ssid=test-ssid&"
                "nasip=10.0.0.1&mac=%s&t=wireless-v2&url=abc123';</script></html>"
                % (PORT, MAC), "text/html")
            return
        if self.path == "/eportal/redirectortosuccess.jsp" and REDIRECT_ENABLED:
            # 真机行为（2026-09-18 确认）：按源 IP 识别会话，302 的 Location
            # 里带回该会话的 userIndex。此处固定返回 REMOTEFROMSERVER，
            # 与拼接值/FORCEFAIL 均不同，供自检区分来源。
            LOG["requests"].append("redirect")
            LOG["counts"]["redirect"] += 1
            LOG["redirect"] = {"path": self.path}
            self.send_response(302)
            self.send_header("Location",
                             "http://127.0.0.1:%d/eportal/success.jsp"
                             "?userIndex=REMOTEFROMSERVER" % PORT)
            self.send_header("Content-Length", "0")
            self.end_headers()
            self._dump()
            return
        self._send("not found", "text/plain", 404)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n).decode("utf-8", "replace")
        form = parse_qs(raw, keep_blank_values=True)
        method = parse_qs(urlparse(self.path).query).get("method", [""])[0]

        if method == "pageInfo":
            LOG["requests"].append("pageInfo")
            LOG["counts"]["pageinfo"] += 1
            qs = form.get("queryString", [""])[0]
            ua = self.headers.get("User-Agent", "")
            LOG["pageinfo"] = {
                "body": raw,
                "referer": self.headers.get("Referer"),
                "queryString": qs,
                "queryString_decoded": unquote(qs),
                "queryString_double_encoded": "%25" in raw,
                "user_agent": ua,
                # 浏览器形态断言用：登录页 JS 是 jQuery ajax 提交
                "xrw": self.headers.get("X-Requested-With"),
                "origin": self.headers.get("Origin"),
                "accept_language": self.headers.get("Accept-Language"),
            }
            # 真实校园网 AC 的行为：请求缺少 User-Agent 时返回 200 + 空 body
            if not ua:
                LOG["pageinfo"]["empty_because_no_ua"] = True
                self._send("", "application/json; charset=UTF-8")
                self._dump()
                return
            self._send(json.dumps({
                "result": "success",
                "publicKeyExponent": "%x" % E,
                "publicKeyModulus": "%x" % N,
                "serviceHtml": '<select><option value="0">校外访问</option>'
                               '<option value="9">中国移动</option></select>',
                "message": "",
            }, ensure_ascii=False))
            self._dump()
            return

        if method == "getServices":
            # 真实 AC（新版 eportal）的运营商接口：返回 "名@名@名" 纯文本（带 JSON 引号）
            LOG["requests"].append("getServices")
            LOG["counts"]["getservices"] += 1
            LOG["getservices"] = {
                "username": form.get("username", [""])[0],
                "search": form.get("search", [""])[0],
            }
            self._send('"中国移动@校园网@中国电信"', "text/html; charset=UTF-8")
            self._dump()
            return

        if method == "login":
            LOG["requests"].append("login")
            LOG["counts"]["login"] += 1
            pwd = form.get("password", [""])[0]
            enc_flag = form.get("passwordEncrypt", [""])[0]
            if enc_flag == "false":
                # 明文提交：服务端直接比对密码本体
                plain, err = pwd, None
                expect = EXPECT_PWD
            else:
                plain, err = decrypt_pwd(pwd)
                expect = "%s>%s" % (EXPECT_PWD, MAC)
            ok = plain == expect
            LOG["login"] = {
                "userId": form.get("userId", [""])[0],
                "service": form.get("service", [""])[0],
                "client_ip": self.client_address[0],
                "passwordEncrypt": enc_flag,
                "password": pwd,
                "password_hex_len": len(pwd),
                "password_decrypted": plain,
                "decrypt_error": err,
                "expect": expect,
                "match": ok,
                "referer": self.headers.get("Referer"),
            }
            user_index = "6e6f6465313233343536" if ok else ""
            self._send(json.dumps({
                "result": "success" if ok else "fail",
                "userIndex": user_index,
                "message": "认证成功" if ok else "密码错误",
            }, ensure_ascii=False))
            self._dump()
            return

        if method == "logout":
            LOG["requests"].append("logout")
            LOG["counts"]["logout"] += 1
            idx = form.get("userIndex", [""])[0]
            LOG["logout"] = {
                "body": raw,
                "userIndex": idx,
            }
            # 传 FORCEFAIL 时返回失败：用于测试"存储的 userIndex 失效后拼接回退"
            if idx == "FORCEFAIL":
                self._send(json.dumps({"result": "fail", "message": "userIndex 不合法"},
                                      ensure_ascii=False))
                self._dump()
                return
            self._send(json.dumps({"result": "success", "message": "注销成功"},
                                  ensure_ascii=False))
            self._dump()
            return

        self._send('{"result":"fail"}')

    def do_HEAD(self):
        self.send_response(404)
        self.end_headers()


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
