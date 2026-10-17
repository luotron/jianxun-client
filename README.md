# 简讯 (jianxun) 登录协议分析与 Python 客户端

对 `简讯` App（`api.jianxun01.com`，Flutter / Dart `3.12.2` AOT）登录会话加密流程的
完整逆向分析，以及一个可直接发包、手机号 + 密码登录的 Python 实现。

> 已在真机抓包 (`cap_lo.pcap`) + 静态逆向 (`libapp.so`) 基础上**端到端验证**：
> 运行 `main.py` 可真实登录并拿到 `token`。

---

## 1. 目标与工具

| 项 | 内容 |
|----|------|
| APK | `w2rkoc_21932.apk`（Flutter 应用，`lib/arm64-v8a/{libapp.so,libflutter.so}`） |
| Dart 版本 | `3.12.2 (stable)`，Snapshot `ace654289f5abc240509fc941453ebc5` |
| 抓包 | `cap_lo.pcap`（`tcpdump -i lo`，经本机代理解了 TLS，但**应用层仍是加密**的） |
| 静态工具 | [blutter](https://github.com/worawit/blutter)（恢复 Dart 符号/对象池）+ IDA Pro（反汇编） |
| 参考 | 《番外实战篇3-拨云见日之浅谈Flutter逆向》 |

逆向思路遵循参考文章：用 blutter 解析快照、把符号脚本加载进 IDA，再定位登录与加解密逻辑。
由于本 App 做了**类名/方法名混淆**，仅字符串字面量与对象池常量可用，因此关键函数是靠
“字符串常量 → 对象池偏移 → 引用该偏移的指令” 这条链在 IDA 里定位的。

---

## 2. 登录请求总览

```
POST https://api.jianxun01.com/v1/user/login
user-agent: Dart/3.12 (dart:io)
content-type: application/json
accept-encoding: gzip
x-timestamp: 1792168342552          # 毫秒时间戳
x-nonce:     23b667406170201e...    # 32 hex 随机 nonce（防重放）
x-sign:      59b8f71b9934d2ba...    # = md5(原始 body 字符串)
token:                              # 登录时为空；登录后为会话 token

{"data":"<base64( nonce12 || AES-256-GCM 密文 || tag16 )>"}
```

响应同样是 `{"data":"<base64(...)>"}`，用**同一把 GCM key**解密。

---

## 3. 会话加密流程（完整还原）

### 3.1 请求体加密 —— AES-256-GCM

`data` 字段的明文是登录 JSON，加密算法为 **AES-256/GCM/NoPadding**：

```
nonce = 12 字节随机                       # sub_5C95AC: 循环 12 次 rng.nextInt(256)
ct, tag = AES-GCM(key=GCM_KEY, nonce).encrypt(utf8(json))
data  = base64( nonce || ct || tag )      # tag 16 字节
```

抓包密文长度 `2028 = 12 + 2000 + 16`、响应 `1236 = 12 + 1208 + 16`，与
“12 字节 nonce 前缀 + GCM tag 后缀”完全吻合（且非 16 对齐，排除了 CBC/ECB）。

### 3.2 GCM 密钥派生（白盒解包）

密钥**不**明文存储，运行时由 `sub_F8D500 → sub_F8D554`（Dart `encrypt` 包）解包：

```
realKey = AES-256/CBC/PKCS7-decrypt(
              base64decode(CONST_BLOB),   # pp+0x93b8
              key = utf8(A),              # 32 字节 → AES-256
              iv  = utf8("8SCXcHDvxLgHa4yK"))   # sub_5CA784, 16 字节
```

其中 `CONST_BLOB = "JzoVVt6fJinbtbOLbM8oS+KBljyAjrauPDdWnH1LxveG7JlyoUPWChbjVoVFJx3k"`。

`A` 由 `sub_5CADB4` 里的 8 个 4-hex 片段按 `k1 k2 k3 k4 x1 x2 x3 x4` 顺序拼接：

| k1 | k2 | k3 | k4 | x1 | x2 | x3 | x4 |
|----|----|----|----|----|----|----|----|
|6a1b|3c7d|9e2f|3a4b|5c6d|7e8f|9a0b|1c2e|

→ `A = "6a1b3c7d9e2f3a4b5c6d7e8f9a0b1c2e"`（32 字符 utf8）

解包结果即 **`GCM_KEY = "3a7b8c9d1e2f3a4b5c6d7e8f9a0b1c2d"`**（32 字节，AES-256）。
`jianxun/crypto.py:derive_gcm_key()` 完整复现该派生，并断言等于用抓包验证过的值。

> 另有一把配置里的默认 `aesKey = "4ciYaGQMpZemFjCB"`、`signKey = "CUCuXP8Q..."`，
> 它们是 dio 选项对象（`sub_10A99F4`）里的字段；真正用于 GCM 的是上面解包出来的
> `GCM_KEY`。

### 3.3 签名 x-sign

```
x-sign = md5( 原始 body 字符串 ).hexdigest()     # sub_528ED8 = md5-hex
       = md5('{"data":"<base64>"}')
```

**不含任何密钥**，是对最终 body 的完整性摘要。已用抓包精确校验：
`md5(捕获 body) == 捕获 x-sign`。

### 3.4 其它请求头

| 头 | 来源 (libapp.so) | 实现 |
|----|------|------|
| `x-timestamp` | `DateTime.now().microsecondsSinceEpoch ~/ 1000` | 当前毫秒 |
| `x-nonce` | md5 的 32-hex 串 | 用随机 nonce（服务端仅用于防重放） |
| `token` | 登录为空，之后带会话 token | — |

---

## 4. 登录明文结构

GCM 解密 `data` 后的登录明文（`sub_10853F4` 构造）：

```json
{
  "username": "qwe778800",             // 用户名账号；手机号账号则是 "0086"+手机号
  "password": "<明文密码>",             // 注意：明文（仅被 GCM 层保护）
  "device": {
    "device_model": "OnePlus_PLR110",
    "device_id":    "bdd9c2b81eaf972c",  // Android ID；陌生设备会触发验证
    "device_name":  "OP6117L1"
  },
  "flag": 0,

  // 陌生设备密保验证时追加（本项目用到的字段）
  "security_question": "儿时养的第一只宠物的名字",
  "security_answer":   "小狗赛虎",

  // App UI 还会带阿里云行为验证码（服务端非必须，见下）
  "captcha_verify_param": "...",
  "need_verify": 1,
  "scene_id": "..."
}
```

- **用户名账号**（如 `qwe778800`）：`username` 直接发原值，响应里 `zone`/`phone` 为空。
- **手机号账号**：`username = 国家码 + 手机号`（如 `008615303021909`）。
- `password` 全程明文，仅靠外层 AES-GCM 保护。

响应明文（成功）：

```json
{"uid":"...","name":"...","username":"qwe778800","phone":"",
 "token":"<会话token>","short_no":"...","setting":{...},
 "rsa_public_key":"<base64 PEM>", ...}
```

### 设备验证（status 110 「新设备需要验证」）

用**未登记过的** `device_id` 登录会返回：

```json
{"msg":"新设备需要验证","status":110,"uid":"..."}
```

处理方式（**已实测**）：

1. 复用**已验证过**的 `device_id` → 直接登录，无需任何验证。
2. 陌生设备 → 在同一个 `/user/login` 请求里追加
   `security_question` + `security_answer`（**密保问题 + 答案**）即可通过，
   **无需阿里云验证码**。`security_question` 发送的是服务端密保问题的**原文**
   （如 `"儿时养的第一只宠物的名字"`），`security_answer` 为答案明文。

本项目的 `login()` 默认走「先普通登录，遇到 110 自动带密保问题重试」的流程
（见 `jianxun/client.py` 的 `login()` / `verify_security()`）。

### device_id 生成算法（`sub_FABB48` / `device_info_plus`）

登录里的 `device.device_id` 是 **Android-ID 形态**：16 位小写十六进制（64-bit，
= 8 字节随机数的 hex）。App 里它来自 `device_info_plus` 插件
（`dev.fluttercommunity.plus/device_info` → `Settings.Secure.ANDROID_ID`）。

App 另外还会在本地 SharedPreferences 用键 `<prefix>_device_id` 持久化一个
**安装 ID** = `uuid.v4().replaceAll('-','')`（32 位 hex，见 `sub_FABB48`：
先读缓存，没有就生成 uuid 去掉 `-` 并写回）。该值用于设备登记等，不是登录
`device_id`。

实测：服务端接受任意合法的 16-hex `device_id`，并据此绑定「账号 ↔ 设备」；
它没见过的设备会触发 `status 110`，用密保问题即可通过。生成脚本：

```bash
python tools/gen_device_id.py                # 16-hex（登录用 device_id）
python tools/gen_device_id.py --style uuid   # 32-hex（App 安装 ID 形态）
python tools/gen_device_id.py --set-config   # 生成并写入 config.json
```

---

## 5. 关键函数索引（libapp.so）


| 地址 | 作用 |
|------|------|
| `0x10853F4` | 登录 API：构造 `{username,password,device,flag,security_question,security_answer,...}` 并 POST `/user/login` |
| `0xF812DC`  | 通用 POST：GCM 加密 body → `{"data":..}`，设置 x-sign/x-nonce/x-timestamp/token |
| `0xF8C4D0`  | AES-GCM 加密（`aQ`=AESEngine，12 字节随机 nonce 来自 `sub_5C95AC`） |
| `0xF8D500/0xF8D554` | GCM 密钥解包（AES-256/CBC/PKCS7，见 3.2） |
| `0x5CADB4/0x5CAA3C` | 组装密钥派生所需的 hex 片段 `A` |
| `0x5CA784`  | 解包用的固定 IV `"8SCXcHDvxLgHa4yK"` |
| `0x528ED8`  | md5-hex（x-sign） |

---

## 6. 使用方法

登录用的**账号（用户名/手机号）、密码、device_id、设备参数、密保问题与答案、
baseUrl 全部放在全局配置文件 `config.json`** 里，直接改这个文件即可：

```json
{
  "base_url": "https://api.jianxun01.com/v1",
  "account": {
    "username": "qwe778800",
    "phone": "",
    "password": "qwe778800",
    "country_code": "0086"
  },
  "device": {
    "device_id": "bdd9c2b81eaf972c",
    "device_model": "OnePlus_PLR110",
    "device_name": "OP6117L1"
  },
  "security": {
    "question": "儿时养的第一只宠物的名字",
    "answer": "小狗赛虎"
  }
}
```

- `account.username` 非空 → 按用户名登录（原值）；留空并填 `account.phone` →
  按手机号登录（实际 `username = country_code + phone`）。
- `security.question` / `security.answer` 用于**陌生设备密保验证**：普通登录遇到
  `status 110` 时自动带上它们重试。

> 配置文件可以只写部分字段，缺省项自动用内置默认值补齐。
> 可用环境变量 `JIANXUN_CONFIG=/path/to/other.json` 或 `--config` 指定其它路径。

```bash
cd ~/code/jianxun-login
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

# 读取 config.json 登录（用户名账号 qwe778800 + 密保）
python main.py

# 模拟陌生设备：随机 device_id 会触发 110，并自动用密保问题验证登录
python main.py --device-id $(python - <<<'import secrets;print(secrets.token_hex(8))')

# 关闭自动验证（陌生设备会直接返回 110 失败）
python main.py --device-id xxxxxxxxxxxx --no-verify

# 覆盖账号 / 密保（命令行优先级高于配置文件）
python main.py --username qwe778800 --password qwe778800 \
               --security-question "儿时养的第一只宠物的名字" --security-answer "小狗赛虎"

# 手机号账号
python main.py --phone 15303021909 --password Asdfghjkl123 --country-code 0086

# 用另一个配置文件
python main.py --config /path/to/other.json
JIANXUN_CONFIG=/path/to/other.json python main.py
```

代码用法（不传参即走 `config.json`）：

```python
from jianxun import JianxunClient, DeviceInfo

c = JianxunClient()
r = c.login()                       # 账号/密码/设备/密保全部来自 config.json
print(r.uid, r.token)               # 陌生设备自动走密保验证

# 显式传参 + 强制陌生设备（演示密保验证请求）
import secrets
r = c.login(
    username="qwe778800", password="qwe778800",
    device=DeviceInfo(device_id=secrets.token_hex(8)),
    security_question="儿时养的第一只宠物的名字", security_answer="小狗赛虎",
)

# 只发“密保验证登录”这一个请求（陌生设备）
data = c.verify_security(security_answer="小狗赛虎",
                         security_question="儿时养的第一只宠物的名字")
# c.token 已被设置，后续 c.request(...) 会自动带上 token 头
```

---

## 7. 目录结构

```
jianxun-login/
├── config.json       # 全局配置：账号/密码/device_id/设备参数/密保问答/baseUrl
├── jianxun/
│   ├── __init__.py
│   ├── config.py     # 配置加载（config.json / $JIANXUN_CONFIG，缺省合并默认值）
│   ├── crypto.py     # GCM 密钥派生 + 加解密 + 签名
│   └── client.py     # JianxunClient / login / verify_security / 错误处理
├── tools/
│   ├── decrypt_capture.py   # 解密抓包 data
│   └── gen_device_id.py     # 生成可用的 device_id
├── main.py           # 命令行入口（config.json 为默认，CLI 可覆盖）
├── requirements.txt
└── README.md
```

---

## 8. 群聊 / 消息功能：接口与协议分析（待抓包验证）

> 结论基于静态逆向（`libapp.so` + blutter 字符串/对象池）+ 对 `GET /v1/group/my`
> 的只读实测。实时消息走**悟空IM（WuKongIM）长连接**，不是 HTTP。开发前请按下方
> 命令抓包验证字段细节。

本应用 IM 基于 **WuKongIM Flutter SDK**（`packages/wukongimfluttersdk/...`）。
两类通道：

- **业务 HTTP**：`https://api.jianxun01.com/v1`，加密信封与登录一致
  （`{"data":AES-GCM}` + `x-sign/x-nonce/x-timestamp/token`，响应也加密）。
  GET 无 body，`x-sign = md5("")`。
- **实时消息**：**悟空IM TCP 长连接** `tcp.jianxun01.com:15100`
  （`socketUrl`，配置可被服务端下发覆盖），自定义二进制协议：
  `Connect→Connack`、`Send→Sendack`、`Recv→Recvack`、`Ping/Pong`。

| 功能 | 通道/协议 | 接口 | 方法 | 说明 |
|------|-----------|------|------|------|
| 获取群列表 | HTTP | `/v1/group/my` | GET | 已实测返回加密数组（无群时 `[]`） |
| 群资料 | HTTP | `/v1/groups/{groupNo}` | GET | 群详情 |
| 获取指定群成员列表 | HTTP | `/v1/groups/{groupNo}/members` | GET | 全量成员 |
| 群成员增量同步 | HTTP | `/v1/groups/{groupNo}/membersync` | GET | `?version=&limit=` 增量 |
| 发送群消息 | **悟空IM TCP** | `SendPacket`（非 HTTP） | — | `channel_id=群号, channel_type=2`(群)，payload 为消息 JSON |
| 接收群消息 | **悟空IM TCP** | `RecvPacket`（服务器下推） | — | 客户端回 `RecvackPacket` |
| 上传图片 | HTTP | `/v1/file/upload` | POST(multipart) | 返回 `oss.jianxun01.com` 上的图片 URL |
| 发送图片消息 | HTTP + 悟空IM | `/v1/file/upload` → `SendPacket` | — | 先上传拿 URL，再发 `type=图片` 的消息 |
| 会话列表同步 | HTTP | `/v1/conversation/sync` | POST | body: `{version,last_msg_seqs,msg_count,device_uuid}` |
| 频道消息历史 | HTTP | `/v1/message/channel/sync` | POST | 拉历史消息 |
| 消息已读/撤回/置顶 | HTTP | `/v1/message/readed` `/message/revoke` `/message/pinned` | POST | 消息扩展 |

> 频道类型（`channel_type`）：`1`=单聊，`2`=群聊（登录后 `conversation/sync`
> 里可见 `channel_id/channel_type`）。群消息的 `channel_id` 即群号。

### 抓包命令（在已 root 真机 / 模拟器上）

和登录一样，HTTP 走本机代理、在 `lo` 上是明文；实时消息是裸 TCP，需另抓其端口。

```bash
# ① HTTP 接口（群列表 / 群成员 / 图片上传 / 会话&消息同步）—— 与登录相同，抓 lo
adb shell su -c "tcpdump -i lo -s 0 -w /sdcard/cap_http.pcap"

# ② 实时消息（悟空IM 长连接：发/收群消息）—— 裸 TCP 二进制，抓 IM 端口（全网卡）
adb shell su -c "tcpdump -i any -s 0 -w /sdcard/cap_im.pcap 'tcp port 15100 or tcp port 15200 or tcp port 5100'"

# 结束后拉取
adb pull /sdcard/cap_http.pcap
adb pull /sdcard/cap_im.pcap
```

对应操作：
- `cap_http.pcap`：进入「群列表」页、打开某群「成员列表」、发一张图片（触发 `/file/upload`）。
- `cap_im.pcap`：在群里发一条文字 + 一张图片，并让该群收到一条消息（接收）。

HTTP 包用本仓库工具解密：

```bash
python tools/decrypt_capture.py '<data字段base64>'
# 或： echo '{"data":"..."}' | python tools/decrypt_capture.py
```

> 若 `cap_im.pcap` 里 15100 端口为 TLS（握手可见 `ClientHello`），需让代理
> 对该 TCP 做 MITM 才能看明文；若是明文二进制（悟空IM 默认），可直接解析
> `Connect/Send/Recv` 包。抓到后我再据此实现 `send_group_message` /
> `recv` / `get_group_members` 等。

---

## 9. 免责声明

仅用于安全研究、互操作性分析与学习目的。请勿用于任何未授权访问或违反服务条款的行为，
由使用本代码产生的一切后果由使用者自行承担。
