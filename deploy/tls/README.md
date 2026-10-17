# deploy/tls — TLS 数据面测试证书与门禁记录

`bicameral/server.py` 的可选 TLS 数据面（`--tls-cert` / `--tls-key` /
`--tls-client-ca`）所用的**固定测试证书**与本地门禁实测记录。

> **仅限测试**：本目录私钥无口令、有效期 10 年、CA 私钥就在旁边 ——
> 生产部署必须换用运维下发的证书，切勿把本目录原样带上生产机。
> `.gitignore` 未排除本目录：这些是公开性质的测试物料，私钥泄露无保护价值。

## 文件清单

| 文件 | 说明 |
| --- | --- |
| `ca.crt` / `ca.key` | 测试 CA（CN=bicameral-test-ca），签发下面两张证书 |
| `server.crt` / `server.key` | 服务端证书（CN=localhost，SAN: localhost,127.0.0.1） |
| `client.crt` / `client.key` | mTLS 客户端证书（CN=bicameral-test-client） |

重新生成（OpenSSL 3.x，命令即本目录证书的实际来源）：

```bash
cd deploy/tls
openssl req -x509 -newkey rsa:2048 -keyout ca.key -out ca.crt -days 3650 -nodes \
  -subj "/CN=bicameral-test-ca"
openssl req -newkey rsa:2048 -keyout server.key -out server.csr -nodes -subj "/CN=localhost"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 3650 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth")
openssl req -newkey rsa:2048 -keyout client.key -out client.csr -nodes -subj "/CN=bicameral-test-client"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 3650 \
  -extfile <(printf "keyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth")
rm -f server.csr client.csr ca.srl && chmod 600 *.key
openssl verify -CAfile ca.crt server.crt client.crt     # -> server.crt: OK / client.crt: OK
```

## server.py 用法

```bash
# TLS（两个平面都走 TLS；/healthz 免 token 但同一 TLS；默认不带这些参数 = 纯 HTTP 不变）
BICAMERAL_ADMIN_TOKEN=<>=16字符> python3 bicameral/server.py \
  --tls-cert deploy/tls/server.crt --tls-key deploy/tls/server.key

# mTLS（额外要求并校验客户端证书）
... --tls-cert deploy/tls/server.crt --tls-key deploy/tls/server.key \
    --tls-client-ca deploy/tls/ca.crt

# 参数红线：只给 --tls-cert 不给 --tls-key（或反之）→ 启动即报错退出，绝不静默回退 HTTP
python3 bicameral/server.py --tls-cert deploy/tls/server.crt
# tls: --tls-cert and --tls-key must be given together (missing --tls-key)   (exit 1)
```

`--selftest` 覆盖参数组合的纯函数用例（`tls.off_by_default` …
`tls.ca_with_half_pair_rejected`，共 7 项）。

## deploy.sh 用法

```bash
# TLS
HOST=... ADMIN_TOKEN=... TLS_CERT=deploy/tls/server.crt TLS_KEY=deploy/tls/server.key \
  ./scripts/deploy.sh
# mTLS（再追加客户端 CA；可选 TLS_CLIENT_CERT/TLS_CLIENT_KEY 供部署后健康检查用）
HOST=... ADMIN_TOKEN=... TLS_CERT=... TLS_KEY=... TLS_CLIENT_CA=deploy/tls/ca.crt \
  TLS_CLIENT_CERT=deploy/tls/client.crt TLS_CLIENT_KEY=deploy/tls/client.key \
  ./scripts/deploy.sh
# 不设 TLS_CERT/TLS_KEY → 与原来完全一致（纯 HTTP，脚本打印提示）
```

脚本行为：证书存在才 scp 上传为远端 `$REMOTE_DIR/tls-*.pem`（0600）并向
`SERVER_ARGS` 追加 `--tls-cert/--tls-key/--tls-client-ca`；部署后健康检查随之切换
为 `curl -k https://…`（mTLS 再带 `--cert/--key`）。只给一半证书对 → 报错退出。

## 本地门禁实测（留档，2026-10-18，主机 nvidia-desktop，端口 18410/18411）

`server.py build dcdea80189f6a19b`；脚本 `set -u`、临时 data-dir、临时端口。

```text
--- [0] --tls-cert without --tls-key -> startup error, exit!=0 ---
tls: --tls-cert and --tls-key must be given together (missing --tls-key)
exit=1

--- [1] no TLS args -> plain HTTP, /healthz 200 over http ---
  -> http_code=200
  -> audit START row tls field: "tls":"off"
  -> server stderr: bicameral up: ... tls=off

--- [2] TLS mode (--tls-cert + --tls-key) ---
server stderr: bicameral up: ... tls=tls
GET  /healthz (no token) over https:  -> http_code=200
POST /issue WITH admin token:         -> http_code=200
POST /issue WITHOUT admin token:      -> http_code=401  {"ok": false, "reason_code": "CTL/AUTH_REQUIRED"}
POST /agent/invoke without cap token: -> http_code=401  {"ok": false, "reason_code": "D1/TOKEN_INVALID"}   (agent plane over TLS)

--- [3] mTLS mode (+ --tls-client-ca deploy/tls/ca.crt) ---
server stderr: bicameral up: ... tls=mtls
GET /healthz with NO client certificate:
  -> curl_exit=56 (TLS handshake failure, no HTTP response)
GET /healthz WITH client certificate:            -> http_code=200
POST /issue with client cert + admin token:      -> http_code=200
agent plane with client cert, no cap token:      -> http_code=401 (D1, TLS 层已过、token 层拒绝)
```

## router.py anchor 外部锚定实测（留档，同日）

`router.py build e5671e11fe7ea472`。`anchor` 把审计链尾（行数/尾 seq/尾行
sha256_16/时间戳）冻结到审计文件之外；默认锚文件为 `<audit>.anchor`，存在即
在每次启动/追加时校验，不匹配在 stderr 响亮告警（fail-loud，不阻断路由）。

```text
--- [a0] anchor over an EMPTY audit -> refuse, exit 2 ---
router: nothing to anchor (audit has no rows): .../empty.jsonl
exit=2

--- [a2] anchor the tail ---
router: anchor written: .../route-audit.jsonl.anchor rows=2 seq=2 tail=698d006001dddea9
anchor file: {"schema": "anchor/1", "ts": ..., "audit": ..., "rows": 2, "seq": 2,
              "tail_sha256_16": "698d006001dddea9"}

--- [a3] legitimate append after anchoring -> silent (startup+append both match)
--- [a4] delete the LAST row (灭迹; in-file chain still VALID) -> startup+append 告警:
router: *** ANCHOR MISMATCH (startup) *** ...anchor: anchored tail=9ba87b3940e979ff but
    the live audit tail is 698d006001dddea9 — rows moved since anchoring. ...
route#4 exit=0   (fail-loud, not fail-stopped; 追加仍是合法恢复路径)

--- [a6] whole audit deleted under an anchor -> anchored tail=... but the live audit
    tail is None — 告警点名"审计整体消失"

--- [a7] anchor over a BROKEN chain -> refuse, exit 2 ---
router: refuse to anchor a BROKEN chain: row 3: prev_sha256_16 '...' does not match
    the previous line '...' (content altered)
```

诚实的边界（与 router.py A2 注释一致）：锚点之后**新追加**的行再被删掉，
文件回到锚定状态，这在密码学上不可分辨（锚只锚"当时之尾"）——
所以自动化闭环是「追加 → 立即重新 anchor」；锚越新，灭迹窗口越小。
