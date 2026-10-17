"""
jianxun.im
==========

简讯 App 的 IM（悟空IM 魔改版）TCP 长连接客户端。

协议为**线上抓包（tcpdump/cap_im*.pcap）+ 真机流量还原**，与开源
`wukongimfluttersdk` 的 MQTT 风格帧格式**完全不同**，是服务端魔改协议：

* 服务器: ``tcp.jianxun01.com:7007``（HTTPDNS 解析到 123.60.87.106；
  备用环境 ``tcp.jianxun02.com:5100`` / 154.23.224.149:5100）。
* 信封（小帧 ≤255 字节）::

      [0x80][u8 总长度][u8 类型字节][内容]

  大帧（如消息密文）不带头直接跟在前面帧之后，长度由帧内字段决定。
* 帧头（内容开头）::

      [u8 a][u8 b][u8 c?][u56 BE 计数器][u32 字段1][u32 = 0x00000014]
      [u32 魔数 = 0x8c7ac0b3][载荷]

  - connect: ``01 01`` + 计数器 + 字段1=0 + 20 + 魔数
  - connack: ``13 01`` + 计数器 + 字段1=0 + 20 + 魔数
  - 消息/确认: ``01 03 01``（消息）``19 01``（sendack）
  - 计数器从 ~4989 起每次 +2（消息序号类字段）
* 载荷**加密**（AES-CBC，密钥由握手协商），16 字节 MD5 用于消息去重/校验。

状态说明
--------

* 帧格式/信封/头结构已从抓包还原（见 README 第 8 节「线上 IM 协议」）。
* **握手载荷加密方案未完全还原**：connect 载荷含 32 位 hex 安装 ID +
  128 字节密文，connack 载荷为密文；已知密钥（GCM key/A 片段/token/uid
  派生）均无法解密，服务端对境外 IP 不响应导致无法在线爆破验证。
* 因此本模块实现了**线上观测到的明文帧结构**，但 send 前会在加密步骤
  报 :class:`WKIMNotImplemented`，不会发出错误格式的数据包。
"""
from __future__ import annotations

import socket
import struct
import time
import uuid
from dataclasses import dataclass, field

DEFAULT_IM_ADDR = "tcp.jianxun01.com:7007"
MAGIC = 0x8C7AC0B3
FIELD_14 = 0x14  # 帧头常量字段（抓包恒为 0x14）
CHANNEL_GROUP = 2

# 域名仅对国内 DNS 解析；这些是抓包/HTTPDNS 实测到的真实服务器地址，
# 域名解析失败时按顺序回退。
_FALLBACK_HOSTS = [
    "123.60.87.106:7007",     # tcp.jianxun01.com 真实地址（HTTPDNS/抓包）
    "154.23.224.149:5100",    # tcp.jianxun02.com 备用环境
]


class WKIMError(Exception):
    pass


class WKIMNotImplemented(WKIMError):
    """协议已还原到明文结构，但该步骤依赖尚未还原的加密算法。"""


@dataclass
class WKIMClient:
    """IM 长连接客户端（信封 + 帧头按线上抓包格式实现）。

    用法::

        im = WKIMClient(uid=..., token=..., device_id=...)
        im.connect()          # 目前会在握手加密处抛 WKIMNotImplemented
        im.send_text(group_no, "hello")
    """

    addr: str = DEFAULT_IM_ADDR
    timeout: float = 10.0
    uid: str = ""
    token: str = ""
    device_id: str = ""

    _sock: socket.socket | None = field(default=None, repr=False)
    _counter: int = 0
    _connected: bool = False

    @property
    def connected(self) -> bool:
        return self._connected

    # ------------------------------------------------------------------ #
    # 线上观测到的明文帧结构
    # ------------------------------------------------------------------ #
    @staticmethod
    def _envelope(content: bytes, typ: int) -> bytes:
        """小帧信封: [0x80][1 + len(content)][type][content]."""
        return b"\x80" + bytes([len(content) + 1]) + bytes([typ]) + content

    @staticmethod
    def _header(a: int, b: int, counter: int, field1: int = 0) -> bytes:
        return (
            bytes([a, b])
            + struct.pack(">Q", counter)[2:]      # u56 BE
            + struct.pack(">I", field1)
            + struct.pack(">I", FIELD_14)
            + struct.pack(">I", MAGIC)
        )

    @staticmethod
    def _header3(a: int, b: int, c: int, counter: int, field1: int = 0) -> bytes:
        return (
            bytes([a, b, c])
            + struct.pack(">Q", counter)[2:]      # u56 BE
            + struct.pack(">I", field1)
            + struct.pack(">I", FIELD_14)
            + struct.pack(">I", MAGIC)
        )

    # ------------------------------------------------------------------ #
    # 连接 / 发送
    # ------------------------------------------------------------------ #
    def connect(self) -> None:
        host, _, port = self.addr.partition(":")
        if not host or not port:
            raise WKIMError(f"无效的 im_addr: {self.addr!r}")
        self._sock = self._dial(host, int(port))
        self._counter = 4989  # 线上观测到的起始计数器

        install_id = uuid.uuid4().hex  # App 的安装 ID 形态（32 位 hex）
        header = self._header(1, 1, self._counter)
        # 载荷：32hex 安装ID + 密文（加密算法未还原，见模块 docstring）
        raise WKIMNotImplemented(
            "IM 握手载荷加密算法尚未还原：connect 的 128 字节密文块无法离线构造，"
            "无法完成安全握手。见 README「线上 IM 协议」一节。"
        )

    def _dial(self, host: str, port: int) -> socket.socket:
        """TCP 连接；域名解析失败时回退到已知真实 IP。"""
        candidates = [(host, port)]
        if host not in [h.split(":")[0] for h in _FALLBACK_HOSTS]:
            for fb in _FALLBACK_HOSTS:
                h2, _, p2 = fb.partition(":")
                if p2 == str(port):
                    candidates.append((h2, int(p2)))
        last_err: OSError | None = None
        for h, p in candidates:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((h, p))
                if h != host:
                    self.addr = f"{h}:{p}"
                return sock
            except OSError as e:
                last_err = e
                continue
        raise WKIMError(f"无法连接 {host}:{port}: {last_err}")

    def close(self) -> None:
        self._connected = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def __enter__(self) -> "WKIMClient":
        if not self._connected:
            self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def send_text(self, channel_id: str, text: str, channel_type: int = CHANNEL_GROUP) -> None:
        raise WKIMNotImplemented(
            "消息载荷加密与握手密钥派生未还原，暂不能发送。"
        )

    def send_image(
        self, channel_id: str, url: str, width: int = 0, height: int = 0,
        channel_type: int = CHANNEL_GROUP,
    ) -> None:
        raise WKIMNotImplemented(
            "消息载荷加密与握手密钥派生未还原，暂不能发送。"
        )
