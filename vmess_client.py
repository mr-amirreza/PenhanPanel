"""VMess Client Engine for SpiderPanel.

Supports parsing vmess:// links and establishing outbound tunnels
(over WebSocket+TLS or Direct TCP/TLS) through external VMess servers.
Compatible with standard VMess AEAD protocol.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import struct
import time
import urllib.parse
import uuid as _uuid
import zlib
from typing import Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

import hmac
_VMESS_CMDKEY_SALT = b"c48619fe-8f02-49e0-b9e9-edf763e17e21"


# ══════════════════════════════════════════════════════════════════════════════
# Diagnostic Trace & Step-by-Step Logger
# ══════════════════════════════════════════════════════════════════════════════
class DiagnosticTrace:
    """Records high-resolution, step-by-step diagnostic events during proxy tests."""
    def __init__(self):
        self.logs = []
        self.start_time = time.monotonic()

    def add(self, stage: str, status: str, message: str, detail: str = ""):
        elapsed = round((time.monotonic() - self.start_time) * 1000, 1)
        self.logs.append({
            "time_ms": elapsed,
            "stage": stage,     # "CONFIG", "DNS", "TCP", "TLS", "WS", "AUTH", "PROBE"
            "status": status,   # "info", "ok", "warn", "error"
            "message": message,
            "detail": detail,
        })

    def to_list(self) -> list:
        return self.logs

    def to_text(self) -> str:
        lines = []
        for l in self.logs:
            st = f"[{l['stage']}]".ljust(9)
            badge = "[OK]  " if l["status"] == "ok" else ("[ERR] " if l["status"] == "error" else "[INFO]")
            line = f"{l['time_ms']:>6.1f}ms {badge} {st} {l['message']}"
            if l.get("detail"):
                line += f" -> {l['detail']}"
            lines.append(line)
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════════════════
# Crypto Helpers (Aligned with relays.py & standard Go VMess AEAD KDF)
# ══════════════════════════════════════════════════════════════════════════════
def _hmac_custom(hash_fn, key: bytes, msg: bytes, block: int = 64) -> bytes:
    """HMAC whose 'hash' is an arbitrary one-shot function (VMess nested KDF)."""
    if len(key) > block:
        key = hash_fn(key)
    key = key.ljust(block, b"\x00")
    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5C for b in key)
    return hash_fn(opad + hash_fn(ipad + msg))


def vmess_kdf(key: bytes, *path: bytes) -> bytes:
    """Official Go-compatible recursive HMAC VMess AEAD KDF."""
    def level(n: int):
        if n == 0:
            return lambda data: hmac.new(b"VMess AEAD KDF", data, hashlib.sha256).digest()
        parent = level(n - 1)
        k = path[n - 1]
        if isinstance(k, str):
            k = k.encode("utf-8")
        return lambda data: _hmac_custom(parent, k, data)
    return level(len(path))(key)


def vmess_kdf16(key: bytes, *path: bytes) -> bytes:
    return vmess_kdf(key, *path)[:16]


def _fnv1a32(data: bytes) -> int:
    h = 0x811C9DC5
    for b in data:
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h


def _chacha_key(key16: bytes) -> bytes:
    first = hashlib.md5(key16).digest()
    return first + hashlib.md5(first).digest()


class _Shake:
    """Lazy SHAKE128 pseudo-random generator with dynamic expansion."""
    def __init__(self, seed: bytes):
        self.seed = seed
        self.size = 2048
        self.data = hashlib.shake_128(seed).digest(self.size)
        self.pos = 0

    def next16(self) -> int:
        if self.pos + 2 > self.size:
            self.size *= 2
            self.data = hashlib.shake_128(self.seed).digest(self.size)
        v = (self.data[self.pos] << 8) | self.data[self.pos + 1]
        self.pos += 2
        return v


class _VMessChunkCrypto:
    """Encodes and decodes VMess AEAD body chunks."""
    TAG = 16

    def __init__(self, security: int, key16: bytes, iv: bytes, opt: int):
        self.security = security
        self.opt = opt
        self.iv = iv
        self.count = 0
        self.len_count = 0
        if security == 3:
            self.aead = AESGCM(key16)
            self.len_aead = AESGCM(vmess_kdf16(key16, b"auth_len"))
        elif security == 4:
            self.aead = ChaCha20Poly1305(_chacha_key(key16))
            self.len_aead = ChaCha20Poly1305(_chacha_key(vmess_kdf16(key16, b"auth_len")))
        elif security == 5:
            self.aead = None
            self.len_aead = None
        else:
            self.aead = AESGCM(key16)
            self.len_aead = AESGCM(vmess_kdf16(key16, b"auth_len"))
        self.masking = bool(opt & 0x04)
        self.padding = bool(opt & 0x08)
        self.auth_len = bool(opt & 0x10) and self.aead is not None
        self.shake = _Shake(iv) if (self.masking or self.padding) else None

    def _nonce(self, count: int) -> bytes:
        return struct.pack(">H", count) + self.iv[2:12]

    def encode_chunk(self, data: bytes) -> bytes:
        if not self.aead:
            return struct.pack(">H", len(data)) + data
        enc = self.aead.encrypt(self._nonce(self.count), data, None)
        self.count += 1
        raw_len = len(enc)
        if self.auth_len:
            nonce = struct.pack(">H", self.len_count) + self.iv[2:12]
            self.len_count += 1
            len_bytes = self.len_aead.encrypt(nonce, struct.pack(">H", raw_len), None)
        else:
            masked = raw_len ^ (self.shake.next16() if self.masking else 0)
            len_bytes = struct.pack(">H", masked)
        return len_bytes + enc

    async def read_chunk(self, reader: asyncio.StreamReader) -> bytes:
        if not self.aead:
            len_b = await reader.readexactly(2)
            length = struct.unpack(">H", len_b)[0]
            if length == 0:
                return b""
            return await reader.readexactly(length)
        if self.auth_len:
            len_b = await reader.readexactly(18)
            nonce = struct.pack(">H", self.len_count) + self.iv[2:12]
            self.len_count += 1
            length = struct.unpack(">H", self.len_aead.decrypt(nonce, len_b, None))[0]
        else:
            len_b = await reader.readexactly(2)
            masked = struct.unpack(">H", len_b)[0]
            length = masked ^ (self.shake.next16() if self.masking else 0)
        if length == 0:
            return b""
        enc = await reader.readexactly(length)
        nonce = self._nonce(self.count)
        self.count += 1
        return self.aead.decrypt(nonce, enc, None)


# ══════════════════════════════════════════════════════════════════════════════
# Link Parsing
# ══════════════════════════════════════════════════════════════════════════════
def parse_vmess_link(raw_link: str) -> dict:
    """Parse a vmess:// link (Base64 JSON or URI-style) into a standardized dictionary."""
    raw = str(raw_link or "").strip()
    if not raw.startswith("vmess://"):
        raise ValueError("Invalid VMess link: must start with vmess://")

    body = raw[len("vmess://"):].strip()

    # Check for URL-style: vmess://uuid@host:port?...#remark
    if "@" in body:
        try:
            parsed = urllib.parse.urlparse(raw)
            uuid_str = parsed.username or ""
            address = parsed.hostname or ""
            port = parsed.port or 443
            ps = urllib.parse.unquote(parsed.fragment or "")
            params = urllib.parse.parse_qs(parsed.query)
            net = (params.get("type", ["tcp"])[0] or params.get("net", ["tcp"])[0]).lower()
            path = params.get("path", ["/"])[0]
            host = params.get("host", [""])[0]
            sni = params.get("sni", [""])[0] or host or address
            security = (params.get("security", ["none"])[0]).lower()
            tls = security == "tls" or params.get("tls", [""])[0] == "tls" or port == 443
            aid = int(params.get("aid", [0])[0] or params.get("alterId", [0])[0] or 0)
            scy = params.get("encryption", ["auto"])[0]
            if not address or not uuid_str:
                raise ValueError("VMess link missing address or uuid")
            return {
                "address": address,
                "port": port,
                "uuid": uuid_str,
                "aid": aid,
                "net": net,
                "path": path if path.startswith("/") else "/" + path,
                "host": host or sni or address,
                "tls": bool(tls),
                "sni": sni,
                "ps": ps,
                "scy": scy,
                "raw": raw,
            }
        except Exception as exc:
            pass

    # Base64 JSON style (v2rayN format)
    pad = len(body) % 4
    if pad:
        body += "=" * (4 - pad)

    try:
        decoded = base64.b64decode(body).decode("utf-8", errors="ignore")
        data = json.loads(decoded)
    except Exception as exc:
        raise ValueError(f"Failed to decode vmess:// payload: {exc}")

    address = str(data.get("add") or "").strip()
    try:
        port = int(data.get("port") or 443)
    except (TypeError, ValueError):
        port = 443
    uuid_str = str(data.get("id") or "").strip()
    aid = int(data.get("aid") or 0)
    net = str(data.get("net") or "tcp").strip().lower()
    path = str(data.get("path") or "/").strip()
    if not path.startswith("/"):
        path = "/" + path
    host = str(data.get("host") or "").strip()
    tls_val = str(data.get("tls") or "").strip().lower()
    tls = tls_val == "tls" or port == 443
    sni = str(data.get("sni") or host or address).strip()
    ps = str(data.get("ps") or "").strip()
    scy = str(data.get("scy") or "auto").strip().lower()

    if not address or not uuid_str:
        raise ValueError("VMess config is missing address or user id (uuid)")

    return {
        "address": address,
        "port": port,
        "uuid": uuid_str,
        "aid": aid,
        "net": net,
        "path": path,
        "host": host or sni or address,
        "tls": tls,
        "sni": sni,
        "ps": ps,
        "scy": scy,
        "raw": raw,
    }


# ══════════════════════════════════════════════════════════════════════════════
# WebSocket Framing (Client-side RFC 6455)
# ══════════════════════════════════════════════════════════════════════════════
def _encode_ws_frame(data: bytes, opcode: int = 2) -> bytes:
    """Encode binary client-to-server WS frame with masking."""
    header = bytearray()
    header.append(0x80 | (opcode & 0x0F))
    length = len(data)
    mask_key = secrets.token_bytes(4)
    if length <= 125:
        header.append(0x80 | length)
    elif length <= 65535:
        header.append(0x80 | 126)
        header.extend(struct.pack(">H", length))
    else:
        header.append(0x80 | 127)
        header.extend(struct.pack(">Q", length))
    header.extend(mask_key)

    masked = bytearray(length)
    for i in range(length):
        masked[i] = data[i] ^ mask_key[i % 4]
    return bytes(header) + bytes(masked)


async def _read_ws_frame(reader: asyncio.StreamReader) -> Tuple[int, bytes]:
    """Read a server-to-client WS frame (unmasked)."""
    b1, b2 = await reader.readexactly(2)
    opcode = b1 & 0x0F
    is_masked = bool(b2 & 0x80)
    length = b2 & 0x7F
    if length == 126:
        length = struct.unpack(">H", await reader.readexactly(2))[0]
    elif length == 127:
        length = struct.unpack(">Q", await reader.readexactly(8))[0]

    mask_key = await reader.readexactly(4) if is_masked else None
    payload = await reader.readexactly(length)
    if is_masked and mask_key:
        unmasked = bytearray(length)
        for i in range(length):
            unmasked[i] = payload[i] ^ mask_key[i % 4]
        payload = bytes(unmasked)
    return opcode, payload


# ══════════════════════════════════════════════════════════════════════════════
# VMess Tunnel Connection
# ══════════════════════════════════════════════════════════════════════════════
class VMessTunnelStream:
    """Provides transparent read/write over a live VMess outbound connection (TCP or WebSocket)."""
    def __init__(
        self,
        raw_reader: asyncio.StreamReader,
        raw_writer: asyncio.StreamWriter,
        enc: _VMessChunkCrypto,
        dec: _VMessChunkCrypto,
        resp_len_key: bytes,
        resp_len_iv: bytes,
        resp_hdr_key: bytes,
        resp_hdr_iv: bytes,
        expected_resp_v: int,
        is_ws: bool = False,
        trace: Optional[DiagnosticTrace] = None,
    ):
        self.raw_reader = raw_reader
        self.raw_writer = raw_writer
        self.enc = enc
        self.dec = dec
        self.resp_len_key = resp_len_key
        self.resp_len_iv = resp_len_iv
        self.resp_hdr_key = resp_hdr_key
        self.resp_hdr_iv = resp_hdr_iv
        self.expected_resp_v = expected_resp_v
        self.is_ws = is_ws
        self.trace = trace

        self._header_decrypted = False
        self._raw_ws_buf = bytearray()
        self._read_buf = bytearray()
        self._closed = False

    async def _read_exact(self, count: int) -> bytes:
        if not self.is_ws:
            return await self.raw_reader.readexactly(count)
        while len(self._raw_ws_buf) < count:
            opcode, payload = await _read_ws_frame(self.raw_reader)
            if opcode == 8:  # WS Close frame
                self._closed = True
                raise asyncio.IncompleteReadError(bytes(self._raw_ws_buf), count)
            if opcode in (1, 2) and payload:
                self._raw_ws_buf.extend(payload)
        out = bytes(self._raw_ws_buf[:count])
        del self._raw_ws_buf[:count]
        return out

    async def write(self, data: bytes):
        if self._closed or not data:
            return
        chunk = self.enc.encode_chunk(data)
        if self.is_ws:
            frame = _encode_ws_frame(chunk, opcode=2)
            self.raw_writer.write(frame)
        else:
            self.raw_writer.write(chunk)
        await self.raw_writer.drain()

    async def read(self, n: int = 4096) -> bytes:
        if self._closed:
            return b""
        while not self._read_buf:
            if not self._header_decrypted:
                if self.trace:
                    self.trace.add("AUTH", "info", "در انتظار پاسخ هدر تاییدیه از سرور VMess...")
                try:
                    resp_enc_len = await self._read_exact(18)
                    resp_len = struct.unpack(">H", AESGCM(self.resp_len_key).decrypt(self.resp_len_iv, resp_enc_len, None))[0]

                    resp_enc_hdr = await self._read_exact(resp_len + 16)
                    resp_hdr = AESGCM(self.resp_hdr_key).decrypt(self.resp_hdr_iv, resp_enc_hdr, None)

                    if resp_hdr[0] != self.expected_resp_v:
                        if self.trace:
                            self.trace.add("AUTH", "error", "کد اعتبارسنجی سرور همخوانی ندارد (Auth Mismatch)")
                        raise ConnectionError("VMess server response auth mismatch")

                    self._header_decrypted = True
                    if self.trace:
                        self.trace.add("AUTH", "ok", f"احراز هویت VMess با موفقیت تایید شد (طول هدر پاسخ: {resp_len} بایت)")
                except Exception as exc:
                    if self.trace:
                        self.trace.add("AUTH", "error", f"خطا در تایید احراز هویت سرور: {exc}")
                    raise

            # Read next body chunk
            try:
                if self.dec.auth_len:
                    len_b = await self._read_exact(18)
                    nonce = struct.pack(">H", self.dec.len_count) + self.dec.iv[2:12]
                    self.dec.len_count += 1
                    length = struct.unpack(">H", self.dec.len_aead.decrypt(nonce, len_b, None))[0]
                else:
                    len_b = await self._read_exact(2)
                    masked = struct.unpack(">H", len_b)[0]
                    length = masked ^ (self.dec.shake.next16() if self.dec.masking else 0)

                if length == 0:
                    self._closed = True
                    return b""

                enc = await self._read_exact(length)
                nonce = self.dec._nonce(self.dec.count)
                self.dec.count += 1
                plain = self.dec.aead.decrypt(nonce, enc, None)
                self._read_buf.extend(plain)
            except (asyncio.IncompleteReadError, ConnectionResetError):
                self._closed = True
                return b""

        out = bytes(self._read_buf[:n])
        del self._read_buf[:n]
        return out

    async def close(self):
        self._closed = True
        try:
            self.raw_writer.close()
            await self.raw_writer.wait_closed()
        except Exception:
            pass


async def open_vmess_outbound(
    cfg: dict,
    target_host: str,
    target_port: int,
    timeout: float = 10.0,
    trace: Optional[DiagnosticTrace] = None,
) -> VMessTunnelStream:
    """Connect to an external VMess server and open a tunnel to target_host:target_port with step-by-step diagnostic trace."""
    if trace is None:
        trace = DiagnosticTrace()

    server_addr = cfg["address"]
    server_port = cfg["port"]
    use_tls = cfg["tls"]
    net = cfg["net"]
    ws_path = cfg["path"]
    ws_host = cfg["host"]
    sni = cfg["sni"]
    uuid_obj = _uuid.UUID(cfg["uuid"])

    trace.add(
        "CONFIG", "info",
        f"آنالیز کانفیگ: {server_addr}:{server_port} (شبکه: {net}{'+tls' if use_tls else ''})",
        f"UUID: {uuid_obj} | Path: {ws_path} | SNI: {sni}"
    )

    # 1. DNS Resolution
    resolved_ip = server_addr
    is_domain = False
    try:
        ipaddress.ip_address(server_addr)
        trace.add("DNS", "info", f"آدرس به صورت IP مستقیم است ({server_addr})")
    except ValueError:
        is_domain = True
        trace.add("DNS", "info", f"در حال استعلام DNS برای دامنه {server_addr}...")
        dns_start = time.monotonic()
        try:
            loop = asyncio.get_running_loop()
            addr_info = await asyncio.wait_for(
                loop.getaddrinfo(server_addr, server_port, proto=socket.IPPROTO_TCP),
                timeout=min(4.0, timeout)
            )
            resolved_ip = addr_info[0][4][0]
            dns_time = round((time.monotonic() - dns_start) * 1000, 1)
            trace.add("DNS", "ok", f"استعلام DNS موفق: {server_addr} -> {resolved_ip}", f"زمان پاسخ: {dns_time}ms")
        except Exception as exc:
            trace.add("DNS", "error", f"خطا در حل نام دامنه DNS: {exc}", "دامنه مسدود است یا رکورد معتبر ندارد")
            raise

    # 2. Open TCP Socket (and optional TLS)
    ssl_ctx = None
    if use_tls:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

    trace.add(
        "TCP", "info",
        f"در حال اتصال سوکت TCP به {resolved_ip}:{server_port}...",
        f"مهلت اتصال: {timeout}s"
    )
    tcp_start = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                server_addr,
                server_port,
                ssl=ssl_ctx,
                server_hostname=sni if use_tls else None,
            ),
            timeout=timeout,
        )
        tcp_ms = round((time.monotonic() - tcp_start) * 1000, 1)
        trace.add("TCP", "ok", f"اتصال سوکت TCP برقرار شد ({tcp_ms}ms)")
        if use_tls:
            trace.add("TLS", "ok", f"هندشیک امنیتی TLS با موفقیت انجام شد (SNI: {sni})")
        else:
            trace.add("TLS", "info", "ارتباط مستقیم ساده (بدون TLS)")
    except asyncio.TimeoutError:
        trace.add("TCP", "error", f"مهلت اتصال به {resolved_ip}:{server_port} تمام شد (Timeout)", "پورت بسته است یا توسط فیلترینگ مسدود شده")
        raise
    except ConnectionRefusedError:
        trace.add("TCP", "error", f"اتصال رد شد (Connection Refused): پورت {server_port} بسته است", "هیچ سرویسی روی این پورت در حال شنود نیست")
        raise
    except Exception as exc:
        trace.add("TCP", "error", f"خطا در برقراری سوکت: {exc}")
        raise

    # 3. WebSocket upgrade if needed
    if net == "ws":
        ws_key = base64.b64encode(secrets.token_bytes(16)).decode()
        req_lines = [
            f"GET {ws_path} HTTP/1.1",
            f"Host: {ws_host}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {ws_key}",
            "Sec-WebSocket-Version: 13",
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "\r\n",
        ]
        trace.add("WS", "info", f"ارسال درخواست ارتقای وب‌سوکت به مسیر {ws_path} (Host: {ws_host})...")
        writer.write("\r\n".join(req_lines).encode())
        await writer.drain()

        try:
            resp_header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=timeout)
            status_line = resp_header.split(b"\r\n")[0].decode(errors="ignore")
            if b" 101 " in resp_header:
                trace.add("WS", "ok", f"ارتقای وب‌سوکت تایید شد ({status_line})")
            else:
                trace.add("WS", "error", f"سرور ارتقای وب‌سوکت را رد کرد: {status_line}", f"پاسخ هدر: {resp_header[:250].decode(errors='ignore')}")
                writer.close()
                raise ConnectionError(f"WebSocket upgrade rejected: {status_line}")
        except asyncio.TimeoutError:
            trace.add("WS", "error", "سرور به درخواست وب‌سوکت در مهلت زمانی پاسخ نداد (Timeout)")
            writer.close()
            raise

    # 4. Build VMess AEAD Client Request Header
    cmd_key = hashlib.md5(uuid_obj.bytes + _VMESS_CMDKEY_SALT).digest()

    now_ts = int(time.time())
    rand_bytes = secrets.token_bytes(4)
    auth_pt = struct.pack(">q", now_ts) + rand_bytes
    auth_pt += struct.pack(">I", zlib.crc32(auth_pt) & 0xFFFFFFFF)
    auth_key = vmess_kdf16(cmd_key, b"AES Auth ID Encryption")
    auth_enc = Cipher(algorithms.AES(auth_key), modes.ECB()).encryptor()
    auth_id = auth_enc.update(auth_pt) + auth_enc.finalize()

    body_iv = secrets.token_bytes(16)
    body_key = secrets.token_bytes(16)
    resp_v = secrets.token_bytes(1)[0]
    opt = 0x05  # chunked + masking
    security = 3  # AES-128-GCM
    cmd = 1       # TCP

    try:
        ip_obj = ipaddress.ip_address(target_host)
        if ip_obj.version == 4:
            atyp = 1
            addr_bytes = ip_obj.packed
        else:
            atyp = 3
            addr_bytes = ip_obj.packed
    except ValueError:
        atyp = 2
        host_utf8 = target_host.encode("utf-8")
        addr_bytes = bytes([len(host_utf8)]) + host_utf8

    hdr = bytearray()
    hdr.append(1)  # Version
    hdr.extend(body_iv)
    hdr.extend(body_key)
    hdr.append(resp_v)
    hdr.append(opt)
    hdr.append(security & 0x0F)
    hdr.append(0)  # Reserved
    hdr.append(cmd)
    hdr.extend(struct.pack(">H", target_port))
    hdr.append(atyp)
    hdr.extend(addr_bytes)
    hdr.extend(struct.pack(">I", _fnv1a32(hdr) & 0xFFFFFFFF))

    nonce = secrets.token_bytes(8)
    len_key = vmess_kdf16(cmd_key, b"VMess Header AEAD Key_Length", auth_id, nonce)
    len_iv = vmess_kdf(cmd_key, b"VMess Header AEAD Nonce_Length", auth_id, nonce)[:12]
    enc_len = AESGCM(len_key).encrypt(len_iv, struct.pack(">H", len(hdr)), auth_id)

    hdr_key = vmess_kdf16(cmd_key, b"VMess Header AEAD Key", auth_id, nonce)
    hdr_iv = vmess_kdf(cmd_key, b"VMess Header AEAD Nonce", auth_id, nonce)[:12]
    enc_hdr = AESGCM(hdr_key).encrypt(hdr_iv, bytes(hdr), auth_id)

    client_handshake = auth_id + enc_len + nonce + enc_hdr

    trace.add(
        "AUTH", "info",
        f"ارسال بسته احراز هویت VMess AEAD ({len(client_handshake)} بایت)...",
        f"مقصد تونل: {target_host}:{target_port}"
    )

    if net == "ws":
        writer.write(_encode_ws_frame(client_handshake, opcode=2))
    else:
        writer.write(client_handshake)
    await writer.drain()

    # 5. Prepare response decryption keys
    rk = hashlib.sha256(body_key).digest()[:16]
    ri = hashlib.sha256(body_iv).digest()[:16]

    resp_len_key = vmess_kdf16(rk, b"AEAD Resp Header Len Key")
    resp_len_iv = vmess_kdf(ri, b"AEAD Resp Header Len IV")[:12]
    resp_hdr_key = vmess_kdf16(rk, b"AEAD Resp Header Key")
    resp_hdr_iv = vmess_kdf(ri, b"AEAD Resp Header IV")[:12]

    enc_crypto = _VMessChunkCrypto(security, body_key, body_iv, opt)
    dec_crypto = _VMessChunkCrypto(security, rk, ri, opt)

    tunnel = VMessTunnelStream(
        raw_reader=reader,
        raw_writer=writer,
        enc=enc_crypto,
        dec=dec_crypto,
        resp_len_key=resp_len_key,
        resp_len_iv=resp_len_iv,
        resp_hdr_key=resp_hdr_key,
        resp_hdr_iv=resp_hdr_iv,
        expected_resp_v=resp_v,
        is_ws=(net == "ws"),
        trace=trace,
    )
    return tunnel


async def vmess_connect_stream_pair(
    cfg: dict,
    target_host: str,
    target_port: int,
    timeout: float = 6.0,
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open a VMess outbound tunnel and wrap it as a standard asyncio StreamReader/StreamWriter pair."""
    tunnel = await open_vmess_outbound(cfg, target_host, target_port, timeout=timeout)
    s1, s2 = socket.socketpair()
    r1, w1 = await asyncio.open_connection(sock=s1)
    r2, w2 = await asyncio.open_connection(sock=s2)

    async def _pump_socket_to_vmess():
        try:
            while True:
                data = await r2.read(32768)
                if not data:
                    break
                await tunnel.write(data)
        except Exception:
            pass
        finally:
            await tunnel.close()
            try:
                w2.close()
            except Exception:
                pass

    async def _pump_vmess_to_socket():
        try:
            while True:
                data = await tunnel.read(32768)
                if not data:
                    break
                w2.write(data)
                await w2.drain()
        except Exception:
            pass
        finally:
            try:
                w2.close()
            except Exception:
                pass
            await tunnel.close()

    asyncio.create_task(_pump_socket_to_vmess())
    asyncio.create_task(_pump_vmess_to_socket())

    return r1, w1


# ══════════════════════════════════════════════════════════════════════════════
# Proxy Connectivity & Latency Tester
# ══════════════════════════════════════════════════════════════════════════════
async def test_vmess_proxy(vmess_cfg: dict, timeout: float = 10.0) -> dict:
    """Test connecting through a VMess proxy with multi-target probe and step-by-step diagnostic logging."""
    trace = DiagnosticTrace()
    result = {
        "protocol": "vmess",
        "ping_ms": None,
        "egress_ip": "",
        "country": "",
        "country_code": "",
        "country_flag": "",
        "working": False,
        "error": "",
        "diagnosis_fa": "",
        "trace": [],
        "trace_text": "",
        "remark": vmess_cfg.get("ps") or "",
        "host": vmess_cfg.get("address") or "",
        "port": vmess_cfg.get("port") or 443,
    }

    tunnel = None
    started = time.monotonic()
    probe_target = "cp.cloudflare.com"
    probe_port = 80

    try:
        # Phase 1: Open tunnel with detailed tracing
        tunnel = await open_vmess_outbound(vmess_cfg, probe_target, probe_port, timeout=timeout, trace=trace)
        ping_ms = round((time.monotonic() - started) * 1000, 1)
        result["ping_ms"] = ping_ms

        # Phase 2: Probe internet traffic (HTTP 204 via Cloudflare)
        trace.add("PROBE", "info", f"ارسال درخواست HTTP به {probe_target}:{probe_port}/generate_204...")
        probe_req = f"GET /generate_204 HTTP/1.1\r\nHost: {probe_target}\r\nConnection: close\r\n\r\n".encode()
        await tunnel.write(probe_req)

        resp_data = await asyncio.wait_for(tunnel.read(1024), timeout=min(6.0, timeout))
        ping_ms = round((time.monotonic() - started) * 1000, 1)
        result["ping_ms"] = ping_ms
        resp_text = resp_data.decode("utf-8", errors="ignore")
        if b"204" in resp_data or b"200" in resp_data or b"HTTP/1." in resp_data:
            trace.add("PROBE", "ok", f"دریافت پاسخ معتبر از اینترنت ({resp_text.splitlines()[0] if resp_text else 'HTTP 204 OK'})", f"تاخیر رفت‌وبرگشت (Real Delay): {ping_ms}ms")
            result["working"] = True
            result["diagnosis_fa"] = f"کانفیگ سالم است و ترافیک اینترنت را با موفقیت عبور می‌دهد (پینگ واقعی: {ping_ms}ms)."
        else:
            trace.add("PROBE", "warn", f"پاسخ غیرمنتظره از تارگت: {resp_text[:100]}")
            result["working"] = True
            result["diagnosis_fa"] = "ارتباط با سرور برقرار شد، اما پاسخ وب نامتعارف بود."

        # Phase 3: Fetch Egress IP if possible
        try:
            ip_tunnel = await open_vmess_outbound(vmess_cfg, "api.ipify.org", 80, timeout=min(5.0, timeout))
            await ip_tunnel.write(b"GET /?format=json HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n")
            ip_data = await asyncio.wait_for(ip_tunnel.read(1024), timeout=4.0)
            ip_text = ip_data.decode("utf-8", errors="ignore")
            await ip_tunnel.close()
            ip_match = re.search(r'"ip"\s*:\s*"([^"]+)"', ip_text)
            if ip_match:
                result["egress_ip"] = ip_match.group(1).strip()
                trace.add("PROBE", "ok", f"آی‌پی خروجی سرور شناسایی شد: {result['egress_ip']}")
            else:
                ips = re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", ip_text)
                if ips:
                    result["egress_ip"] = ips[0]
                    trace.add("PROBE", "ok", f"آی‌پی خروجی سرور شناسایی شد: {result['egress_ip']}")
        except Exception as _e_ip:
            trace.add("PROBE", "info", f"استعلام آی‌پی خروجی رد شد: {_e_ip}")

        # Resolve country metadata
        rem = vmess_cfg.get("ps") or ""
        match_flag = re.search(r"[\U0001F1E6-\U0001F1FF]{2}", rem)
        if match_flag:
            result["country_flag"] = match_flag.group(0)
            c1 = chr(ord(result["country_flag"][0]) - 127397)
            c2 = chr(ord(result["country_flag"][1]) - 127397)
            result["country_code"] = (c1 + c2).upper()
        if not result["country_code"]:
            m_code = re.search(r"\b(US|DE|FR|GB|UK|NL|FI|TR|CA|SG|JP|KR|AE|PL|SE|CH)\b", rem.upper())
            if m_code:
                c = m_code.group(1)
                if c == "UK": c = "GB"
                result["country_code"] = c
                result["country_flag"] = chr(127397 + ord(c[0])) + chr(127397 + ord(c[1]))
        if not result["country_flag"]:
            result["country_flag"] = "🌐"
        if not result["country"]:
            names_map = {
                "US": "United States", "DE": "Germany", "FR": "France", "GB": "United Kingdom",
                "NL": "Netherlands", "FI": "Finland", "TR": "Turkey", "CA": "Canada",
                "SG": "Singapore", "JP": "Japan", "KR": "South Korea", "AE": "UAE",
                "PL": "Poland", "SE": "Sweden", "CH": "Switzerland", "IR": "Iran"
            }
            result["country"] = names_map.get(result["country_code"], result["country_code"] or "External VMess")

    except asyncio.TimeoutError:
        result["error"] = "سرور پاسخ نمی‌دهد (Timeout)"
        last_stage = trace.logs[-1]["stage"] if trace.logs else "UNKNOWN"
        if last_stage in ("TCP", "DNS"):
            result["diagnosis_fa"] = "آی‌پی سرور در شبکه در دسترس نیست یا پورت توسط فیلترینگ مسدود شده است."
        elif last_stage == "AUTH":
            result["diagnosis_fa"] = "سوکت وصل شد اما سرور بسته احراز هویت VMess را رد کرد؛ احتمالاً UUID منقضی است یا پکت‌ها مسدود می‌شوند."
        else:
            result["diagnosis_fa"] = "مهلت زمانی تمام شد (Timeout)."
    except ConnectionRefusedError:
        result["error"] = "ارتباط رد شد (پورت بسته است)"
        result["diagnosis_fa"] = "پورت مقصد روی سرور بسته است یا سرویسی روی آن اجرا نمی‌شود."
    except ConnectionResetError:
        result["error"] = "ارتباط قطع شد (Connection Reset)"
        result["diagnosis_fa"] = "اتصال بلافاصله توسط سرور یا سیستم فیلترینگ ریست شد."
    except Exception as exc:
        msg = str(exc)
        result["error"] = msg[:160] or type(exc).__name__
        if "WebSocket upgrade rejected" in msg:
            result["diagnosis_fa"] = "مسیر وب‌سوکت اشتباه است یا ورکر/CDN سرویس‌دهنده غیرفعال شده است (404/403)."
        elif "getaddrinfo failed" in msg or "Name or service not known" in msg:
            result["diagnosis_fa"] = "نام دامنه سرور یافت نشد؛ دامنه فاقد رکورد معتبر است یا DNS مسدود شده."
        else:
            result["diagnosis_fa"] = f"خطا در برقراری ارتباط: {result['error']}"
    finally:
        if tunnel:
            await tunnel.close()

    result["trace"] = trace.to_list()
    result["trace_text"] = trace.to_text()
    return result
