# 简讯 (jianxun) 登录协议分析与 Python 客户端

对 `简讯` App（`api.jianxun01.com`，Flutter / Dart `3.12.2` AOT）登录会话加密流程的
完整逆向分析，以及一个可直接发包、手机号 + 密码登录的 Python 实现。

已补齐 IM 长连接：通过 AppVest 网关连接 WuKongIM v4，在同一个 socket 上完成
消息发送、接收、回执和心跳；两个测试账号的私聊双向收发及测试群消息收发均已实测。
详细证据与原生函数地址见 [Socket 分析报告](doc/2026-10-19_逆向-jianxun-socket-report.md)。

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

### 密保问题选择有哪些选项（security_question 选项分析）

> 结论基于 `libapp.so` 静态分析（IDA，字符串池 + 流程交叉定位）。
> 关键点：**客户端没有内置任何密保问题文本**，问题列表全部由服务端下发；
> 客户端只硬编码了「问题类型」两个枚举值。

陌生设备登录触发验证后的完整 UI 流程（按字符串证据还原）：

```
POST /user/login (新 device_id)
  → status 110 "新设备需要验证"
  → /IdentityAuthPage
      "For account security, we need to verify your identity"   (0x11de08)
      验证方式选项：手机验证码 / 人脸(肖像) / 密保问题 等
      （"New device login, please use verification code login" 0x8f285、
        "Portrait Authentication" 0xe8f0e）
  → 选「密保问题」→ 先调 getSecurityQuestion 拉取问题列表
      "Please get security question first" (0x1399d0 / pleaseGetSecurityQuestion 0x13c79c)
  → 从列表里选中账号设置的密保问题
      "Please select your security question" (0xb9b73)
  → 输入答案 "Enter security question answer" (0xb4ed9)
  → 重发 /user/login，body 追加 security_question（问题原文）+ security_answer
```

「选择」层有且仅有 **2 个客户端内置选项**（`questionType` 枚举，标签
`"Question Type"` 0x159b17）：

| questionType 值 | 界面文案 | 字符串地址 |
|-----------------|----------|-----------|
| `quickQuestion` | `Quick Question` | 0xad525 / 0xf6d75 |
| `commonQuestion` | `Common Question` | 0x12fbca / 0x12d88b |

这两个只是**问题分类**（对应设置页 `SetSecurityQuestionPage` 的分组 Tab）；
每个分类下**具体的问题文本（如 `"儿时养的第一只宠物的名字"`）不在客户端里**，
由服务端 `getSecurityQuestion` 接口返回。因此静态分析无法枚举完整问题列表，
要拿到全部选项需抓取该接口的响应（或在 App 内走一遍设置密保页）。

客户端其它相关分支（字符串证据）：

| 场景 | 字符串 | 地址 |
|------|--------|------|
| 未设置过密保 | `You have not set security questions, go to set?` / `goToSetSecurityQ` | 0xc7dbf / 0x167704 |
| 设置页路由 | `/SetSecurityQuestionPage` | 0x7837e |
| 设置新问题 | `Please select a new security question` / `pleaseSelectNewSecurityQuestion` / `newSecurityQuestion` | 0xa8c0c / 0x15e1f9 / 0x157838 |
| 找回密码选旧问题 | `verifyYourSecurityQuestionRecover` / `pleaseSelectOldSecurityQuestion` / `Please select an old security question` | 0xaa657 / 0x109a46 / 0x13086e |
| 答案校验 | `answerTooShort` | 0xc2d51 |
| 请求字段 | `security_question` / `ori_security_question` / `new_security_question` / `security_answer` / `ori_security_answer` / `new_security_answer` | 0x97bdc / 0x83100 / 0x110111 / 0x11da00 / 0xdb163 / 0x928f7 |

> 字段命名说明：登录请求用 `security_question` + `security_answer`（本项目已实现）；
> 修改密保时用 `ori_security_question/ori_security_answer`（旧值）+
> `new_security_question/new_security_answer`（新值），提交到设置页对应接口。

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
baseUrl 全部放在全局配置文件 `config.json`** 里，直接改这个文件即可（`token`
由程序登录成功后自动写回，无需手工维护）：

```json
{
  "base_url": "https://api.jianxun01.com/v1",
  "token": "cb56ea29e63a4f53ab3bbf2354d0f122",
  "uid": "b70b1f5f2d0c4337ad42e87429b9af65",
  "im_addr": "tcp.jianxun01.com:15100",
  "im_transport": "appvest",
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
- `token` / `uid`：登录成功后自动写入 `config.json`；下次启动可直接复用
  token 免登录。
- `im_addr`：悟空IM 逻辑目标地址，保持 `tcp.jianxun01.com:15100`；
  AppVest 握手需要完整的域名和端口，不能用解析后的 IP 替换。
- `im_transport`：默认 `appvest`，先发现可用网关，再完成 IM 认证。
  `direct` 表示直连逻辑目标；本次线上验证使用 `appvest`。
- `qlck`：可选对象，对应 `QLCKOptions`；默认启用网关发现。
  手工固定网关时可设置 `{"gateway":"220.185.183.254:80","discover":false}`，
  该地址是本次实测节点，后续以调度返回的节点为准。

> 配置文件可以只写部分字段，缺省项自动用内置默认值补齐。
> 可用环境变量 `JIANXUN_CONFIG=/path/to/other.json` 指定其它路径。

### 6.1 交互式运行（无命令行参数）

`python main.py` 启动后**默认使用已保存的 token**；token 过期/失效时自动改用
`config.json` 的账号密码（或手机号密码）登录，并把新 token 写回配置文件。登录后
通过命令行交互拉取群列表、选择指定群查看成员列表或群资料：

```
$ python main.py
简讯 (jianxun) 命令行客户端
------------------------------------------------------------
[*] config   : C:\...\config.json
[*] base_url : https://api.jianxun01.com/v1
[*] 账号     : aa115566 (用户名账号)
[*] 使用已保存 token: cb56ea29...
[+] token 有效

请选择操作:
  1. 查询群（选择群查看成员列表 / 群资料）
  2. 重新登录
  3. 退出
> 1
[*] 共 1 个群:
    1. 测试群  (9c509b80996e4ee8a1d315063c9b940a) 成员:2
选择群 (1-1，回车返回主菜单): 1

当前群: 测试群 (9c509b80996e4ee8a1d315063c9b940a)
请选择操作:
  1. 查询群成员列表
  2. 查询群资料
  3. 发送文字消息
  4. 发送图片
  5. 查看历史并持续监听群消息
  6. 返回群列表
> 1
...
```

行为约定：

| 场景 | 行为 |
|------|------|
| 启动（有 token） | 默认复用 config.json 的 `token`，用 `/group/my` 探活校验 |
| token 过期/失效 | 自动改用 config.json 账号密码（或手机号密码）登录，成功后 token 写回 `config.json` |
| 账号类型 | `account.username` 非空 → 用户名登录；否则 `country_code + phone` 手机号登录 |
| 陌生设备 (110) | 自动带 `security_question/answer` 重试（config 里配置） |
| **要求阿里云行为验证码 (220)** | **取消登录**：打印提示并退出（本客户端不接验证码） |
| 查询群 | 拉取群列表 → 交互选择群号 → 查看群成员列表 / 群资料 |
| 重新登录 | 菜单选 2，立即用 config.json 重新登录并刷新 token |

```bash
cd ~/code/jianxun-login
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

python main.py                 # 交互式运行（默认 config.json）
JIANXUN_CONFIG=/path/to/other.json python main.py   # 用另一个配置文件
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

# 登录成功后可把 token 持久化到 config.json（等价于 CLI 里的自动保存）
from jianxun.config import Config
Config.load().save_token(r.token)
```

> 服务端要求行为验证码时（`status 220`，App 端会弹出腾讯/阿里云滑块并带
> `captcha_verify_param` 重试），本客户端抛 `CaptchaRequired`，调用方应取消
> 登录。静态分析依据：登录响应处理函数（`sub_1084884`/`sub_1085CF4`）对
> `status == 220` 分支跳转到验证码页（`/files/captcha.html`，腾讯 TCaptcha
> appid `189939519`）。

---

## 7. 目录结构

```
jianxun-login/
├── config.json       # 全局配置：账号/密码/device_id/设备参数/密保问答/baseUrl
├── jianxun/
│   ├── __init__.py
│   ├── config.py     # 配置加载（config.json / $JIANXUN_CONFIG，缺省合并默认值）
│   ├── crypto.py     # GCM 密钥派生 + 加解密 + 签名
│   ├── client.py     # JianxunClient / login / 群查询 / 图片上传 / 错误处理
│   ├── im.py         # 悟空IM TCP 长连接（X25519 + AES、发送/接收、回执与心跳）
│   └── qlck.py       # AppVest 网关发现、488 字节握手和双向 XOR 传输
├── tools/
│   ├── decrypt_capture.py   # 解密抓包 data
│   ├── gen_device_id.py     # 生成可用的 device_id
│   ├── im_probe.py          # 复用已保存 token，独立测试单 socket 收发
│   ├── analyze_im_capture.py # 重组 TCP、解析 AppVest / IM 抓包
│   └── verify_qlck_native.py # ARM64 原生握手与 Python 字节对照
├── tests/test_im.py  # 分帧、抓包、单连接并发收发/心跳测试
├── main.py           # 交互式命令行入口（默认复用 token，失效自动登录；群列表选择查询）
├── requirements.txt
└── README.md
```

---

## 8. 群聊 / 消息功能：接口与协议分析

> 结论基于静态逆向（`libapp.so` + blutter 字符串/对象池）+ `tcpdump/cap_http.pcap`
> 抓包解密验证（点开群列表 / 查看群成员的手动操作）。**群列表与群成员接口已在本
> 项目实现**（`jianxun/client.py` 的 `get_group_list()` / `get_group_members()`，
> CLI 见下）。实时消息走**悟空IM（WuKongIM）长连接**，不是 HTTP。

本应用 IM 基于 **WuKongIM Flutter SDK**（`packages/wukongimfluttersdk/...`）。
两类通道：

- **业务 HTTP**：`https://api.jianxun01.com/v1`，加密信封与登录一致
  （`{"data":AES-GCM}` + `x-sign/x-nonce/x-timestamp/token`，响应也加密）。
  GET 无 body，`x-sign = md5("")`。
- **实时消息**：通过 **AppVest 网关**访问逻辑目标 `tcp.jianxun01.com:15100`，
  网关首包后是 XOR 传输的 WuKongIM v4 二进制协议：
  `Connect→Connack`、`Send→Sendack`、`Recv→Recvack`、`Ping/Pong`。

| 功能 | 通道/协议 | 接口 | 方法 | 说明 |
|------|-----------|------|------|------|
| 获取群列表 | HTTP | `/v1/group/my` | GET | **已实现+实测**：加密数组（无群时 `[]`），元素即群资料对象 |
| 群资料 | HTTP | `/v1/groups/{groupNo}` | GET | **已实现+实测**（`cap_http.pcap`）：完整群详情，见下方响应示例 |
| 获取指定群成员列表 | HTTP | `/v1/groups/{groupNo}/members` | GET | **已实现+实测**：`?keyword=&limit=50&page=1` 分页，非群成员报 400 |
| 群成员增量同步 | HTTP | `/v1/groups/{groupNo}/membersync` | GET | `?version=&limit=` 增量 |
| 发送文字消息 | **悟空IM TCP** | `SendPacket`（`jianxun/im.py`） | — | **已实现**：`channel_id=群号, channel_type=2`，payload `{"content":"...","type":1}` |
| 发送图片 | HTTP + 悟空IM | `/v1/file/upload` → `SendPacket` | — | **已实测**：读取 PNG/JPEG 真实尺寸，上传后用返回的预览 `path` 构造图片消息 |
| 接收群消息 | **悟空IM TCP** | `RecvPacket`（服务器下推） | — | 客户端回 `RecvackPacket`（`im.py` 已实现解析/校验/回执） |
| 会话列表同步 | HTTP | `/v1/conversation/sync` | POST | body: `{version,last_msg_seqs,msg_count,device_uuid}`（抓包已解出） |
| 频道消息历史 | HTTP | `/v1/message/channel/sync` | POST | 拉历史消息 |
| 消息已读/撤回/置顶 | HTTP | `/v1/message/readed` `/message/revoke` `/message/pinned` | POST | 消息扩展 |

> 频道类型（`channel_type`）：`1`=单聊，`2`=群聊（登录后 `conversation/sync`
> 里可见 `channel_id/channel_type`）。群消息的 `channel_id` 即群号。

### 已抓包验证的接口与响应（`tcpdump/cap_http.pcap` 解密结果）

抓包中「点开群列表」时 App 依次调用：`GET /v1/group/my`（列表）→ 逐群
`GET /v1/groups/{groupNo}`（详情，响应含 `member_count/online_count`）；
「查看群成员」调用 `GET /v1/groups/{groupNo}/members?keyword=&limit=50&page=1`。

`GET /v1/groups/{groupNo}` 解密响应（群资料）：

```json
{"group_no":"9c509b80996e4ee8a1d315063c9b940a","group_type":0,"category":"",
 "name":"测试群","remark":"","notice":"","mute":0,"top":0,"show_nick":0,
 "save":0,"forbidden":0,"invite":0,"chat_pwd_on":0,"screenshot":1,
 "revoke_remind":1,"join_group_remind":0,"forbidden_add_friend":0,
 "status":1,"receipt":1,"flame":0,"flame_second":0,
 "allow_view_history_msg":1,"member_count":2,"online_count":1,"quit":0,
 "role":0,"forbidden_expir_time":0,"allow_member_pinned_message":0,
 "created_at":"2026-10-17 21:25:29","updated_at":"2026-10-17 21:25:29",
 "version":1097147,"allow_group_member_list":"1","level":"",
 "expire_time":null,"Creator":"25916f7ffb7d4a6c860afcb9f4fa0d0b"}
```

`GET /v1/groups/{groupNo}/members?keyword=&limit=50&page=1` 解密响应（成员数组，
`role`: 1=群主，0=普通成员）：

```json
[{"id":145382,"uid":"25916f7ffb7d4a6c860afcb9f4fa0d0b",
  "group_no":"9c509b80996e4ee8a1d315063c9b940a","name":"测试","remark":"",
  "role":1,"version":1288198,"is_deleted":0,"status":1,"vercode":"",
  "invite_uid":"25916f7ffb7d4a6c860afcb9f4fa0d0b","robot":0,
  "forbidden_expir_time":0,"friend_remark":"",
  "created_at":"2026-10-17 21:25:29","updated_at":"2026-10-17 21:25:29",
  "is_white_list":0,"is_member":0,"background_color":1,"nickname_color":1,
  "is_pretty":0}, ...]
```

调用方式（交互式菜单，启动默认复用 token，失效自动登录；菜单选「查询群」）：

```
python main.py
> 1 查询群 → 拉取 /group/my 群列表
  选择群 (1-N): 1
  当前群: 测试群 (9c509b80996e4ee8a1d315063c9b940a)
    1. 查询群成员列表   (GET /groups/{groupNo}/members，自动翻页拉全量)
    2. 查询群资料       (GET /groups/{groupNo})
    3. 发送文字消息     (悟空IM SendPacket)
    4. 发送图片         (/v1/file/upload 上传 → 悟空IM SendPacket)
    5. 查看历史并持续监听群消息 (先显示历史，再用同一长连接持续接收)
    6. 返回群列表
```

### 悟空IM（WuKongIM）长连接 —— `jianxun/im.py` + `jianxun/qlck.py`

2026-10-19 已完成线上验证：连接、群文本发送、第二账号接收解密、私聊双向收发。
底层链路为 `Flutter → flutter_qlck → AppVest → WuKongIM v4`。
本次实测数据网关为 `220.185.183.254:80`，逻辑目标保持
`tcp.jianxun01.com:15100`。此前将独立的 7007 流误判为 IM 协议，本节已更正。

`libcf-msc.so` 的原生函数构造 488 字节网关握手，后续字节流与设备指纹
首字符的 ASCII 值异或；还原后是 `CONNECT/CONNACK`、`SEND/SENDACK`、
`RECV/RECVACK` 和 `PING/PONG`。IM 使用 X25519 协商及 AES-CBC 消息加密。
文本载荷为 `{"content":"...","type":1}`，图片载荷为
`{"width":320,"height":180,"url":"file/preview/chat/2/...","type":2}`。
图片宽高必须大于 0；菜单先识别 PNG/JPEG 尺寸，识别失败时提示错误，不上传、不发送。

群菜单选择「4. 发送图片」后，会直接弹出文件选择窗口，无需输入本地路径。
选中 PNG/JPG/JPEG 并点击「打开」即开始上传和发送，取消选图返回群菜单。
需要在有图形桌面的环境中运行；Windows 官方 Python 安装时需包含 Tcl/Tk，
Ubuntu/Debian 缺少 Tkinter 时可运行 `sudo apt install python3-tk`。

客户端只有一个后台读取线程，把 SENDACK 和收到的消息分别分发；发送、接收和
心跳共用同一个 socket。等待接收超时不会关闭连接。发送成功以
`ack.success`（`reason_code == 1`）为准；发送回执超时表示接收状态未知，
客户端不会自动重发。

复用当前 `config.json` 中已保存的 `uid/token`，无需先调用 HTTP 群列表接口：

```powershell
# 连接并向测试群发送一条文字，输出服务端 SENDACK
python tools/im_probe.py --channel 9c509b80996e4ee8a1d315063c9b940a --channel-type 2 --text "Socket脚本测试" --out doc/ida_socket/manual_send.json

# 保持连接并等待一条推送，期间可从另一个账号向该账号或其所在群发消息
python tools/im_probe.py --receive 60 --out doc/ida_socket/manual_receive.json

# 发送后在同一个 socket 上等待一条推送
python tools/im_probe.py --channel 9c509b80996e4ee8a1d315063c9b940a --text "单连接收发测试" --receive 60
```

`--receive` 收到一条推送即结束，超时返回非零退出码；发送后不保证收到自己的
消息回推，收消息测试应由另一个账号发消息。私聊使用 `--channel-type 1`，
`--channel` 填对方 uid。其他账号可用 `--config` 指定各自的配置文件。

历史查看、持续监听和消息发送统一使用交互式主程序：

```powershell
python main.py
```

选择「1 查询群」→ 选择群 →「5 查看历史并持续监听群消息」，输入历史条数
（默认 20，输入 0 只监听新消息）。程序先建立 IM 长连接，让后台开始缓存推送，
然后调用 `/v1/message/channel/sync` 显示历史，最后持续打印该群的新消息。
按 Ctrl+C 返回群菜单，保留当前连接，可继续发文字、图片或重新监听。
离开该群才关闭连接。历史和实时推送重叠的消息按 message_id 去重，
其他群与私聊推送不显示。历史接口超时会显示错误并继续实时监听。
历史消息和新消息均显示时间、发送者、消息序号及文字/图片地址。

最新群发送回执保存在 [live_group_script.json](doc/ida_socket/live_group_script.json)：
标记 `JX-SOCKET-1019`，`message_id=2112165339868344320`，
`message_seq=15`，`reason_code=1`。第二账号群消息接收证据见
[live_group_message.json](doc/ida_socket/live_group_message.json)，双向私聊证据见
[live_bidirectional.json](doc/ida_socket/live_bidirectional.json)。

**图片上传（HTTP，已实测，见 `cap_http.pcap`）**：

```
GET  /v1/file/upload?path=%2F2%2F<groupNo>%2F<uuid32>&type=chat
       → {"url":"https://api.jianxun01.com/v1/file/upload?type=chat&path=/2/<groupNo>/<uuid>"}
POST <该url>  multipart 字段 file（x-sign 头为字面量 "x-sign"，与 App 一致）
       → {"path":"file/preview/chat/2/<groupNo>/<uuid>",
           "url":"https://zy-jp-prod2.oss-ap-northeast-1.aliyuncs.com/chat/2/<groupNo>/<uuid>"}
```

图片消息的 `url` 使用上传返回的 `path`（`file/preview/...`），与原 App 一致；
上传返回的另一个 `url` 是 OSS 存储地址。
2026-10-20 已通过 `main.py` 群菜单第 4 项实测 PNG 上传与发送：
群序号 22，第二账号收到 `320×180` 的图片载荷，预览接口返回的文件与上传原图一致。
证据见 [图片发送验证](doc/ida_socket/live_image_send_20261020.json)。
测试覆盖客户端链路，未通过手机截图核对显示结果。

```python
from jianxun import JianxunClient

c = JianxunClient()
c.login()

groups = c.get_group_list()          # list[dict]，[] 表示无群
g = c.get_group(groups[0]["group_no"])
members = c.get_group_members(g["group_no"], keyword="", limit=50, page=1)
all_members = c.get_all_group_members(g["group_no"])   # 自动翻页拉全量
for m in members:                    # GroupMember: uid/name/role/raw
    print(m.uid, m.name, "群主" if m.role == 1 else "成员")
```

> 注意：非群成员调用 `/groups/{groupNo}` 及 members 接口会返回
> `400 非群成员不允许操作`（本客户端抛 `ApiError`）。

### 抓包命令（在已 root 真机 / 模拟器上）

和登录一样，HTTP 走本机代理、在 `lo` 上可见应用层密文；实时消息需同时抓取
AppVest 数据网关的 80 端口及控制通道的 8080 端口。

```bash
# ① HTTP 接口（群列表 / 群成员 / 图片上传 / 会话&消息同步）—— 与登录相同，抓 lo
adb shell su -c "tcpdump -i lo -s 0 -w /sdcard/cap_http.pcap"

# ② 实时消息和 AppVest 调度（全网卡）
adb shell su -c "tcpdump -i any -s 0 -w /sdcard/cap_im.pcap 'tcp port 80 or tcp port 8080 or tcp port 15100'"

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

已有抓包可直接离线分析。`cap_im4.pcap` 的设备指纹首字符为 `E`，异或值为
`0x45`；其他抓包应按各自的握手指纹选择异或值：

```powershell
python tools/analyze_im_capture.py tcpdump/cap_im4.pcap --peer 106.53.220.67 --xor 0x45 --out doc/ida_socket/cap_im4_decoded.json
python -m unittest discover -s tests -v
```

---

## 9. 免责声明

仅用于安全研究、互操作性分析与学习目的。请勿用于任何未授权访问或违反服务条款的行为，
由使用本代码产生的一切后果由使用者自行承担。
